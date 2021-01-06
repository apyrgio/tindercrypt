//! # Cryptor structs for encryption/decryption
//!
//! A cryptor is a struct with methods that can encrypt (seal) a plaintext or
//! decrypt (open) a ciphertext. This module provides [`RingCryptor`], a
//! cryptor struct that provides the above functionality using various `ring`
//! cryptographic primitives.
//!
//! [`RingCryptor`]: struct.RingCryptor.html

use crate::aead;
use crate::errors;
use crate::metadata;
use crate::pbkdf2;
use ring;
use zeroize;

/// A cryptor that uses cryptographic primitives from the `ring` crate.
///
/// If a user wants to encrypt a plaintext, they can use one of the `.seal_*`
/// methods of the cryptor. In a nutshell, the encryption logic is the
/// following:
///
/// * Choose a key derivation and encryption algorithm.
/// * Generate the [metadata] for these algorithms.
/// * Serialize the [metadata] into a buffer large enough to hold the
///   ciphertext and its tag.
/// * Copy the plaintext in a specific position within the buffer.
/// * Derive a symmetric key from a passphrase, if the PBKDF2 key derivation
///   algorithm is used.
/// * Encrypt the data in place. The original plaintext is not affected since
///   it's a copy.
/// * Return the buffer with the serialized metadata, ciphertext and tag.
///
/// If a user wants to decrypt a plaintext, they can use one of the `.open_*`
/// methods of the cryptor. In a nutshell, the decryption logic is the
/// following:
///
/// * Deserialize the [metadata] from the buffer header. Return an error if
///   they are corrupted or don't exist.
/// * Copy the ciphertext into a new buffer.
/// * Derive a symmetric key from a passphrase, if the PBKDF2 key derivation
///   algorithm is used.
/// * Decrypt the data in place, or return a decryption error. The original
///   ciphertext is not affected, since it's a copy.
/// * Return the plaintext.
///
/// The user can skip some of the copies and allocations, depending on which
/// cryptor methods they choose to use.
///
/// ## Examples
///
/// The simplest way to encrypt a plaintext with a passprhase is the following:
///
/// ```
/// use tindercrypt::cryptors::RingCryptor;
///
/// let plaintext = "The cake is a lie".as_bytes();
/// let pass = "My secret passphrase".as_bytes();
/// let cryptor = RingCryptor::new();
///
/// let ciphertext = cryptor.seal_with_passphrase(pass, plaintext)?;
/// let plaintext2 = cryptor.open(pass, &ciphertext)?;
/// assert_eq!(plaintext2, plaintext);
///
/// # use tindercrypt::errors;
/// # Ok::<(), errors::Error>(())
/// ```
///
/// If the user can create their own buffers beforehand, the no-allocation path
/// is the following:
///
/// ```
/// use tindercrypt::metadata::Metadata;
/// use tindercrypt::cryptors::RingCryptor;
///
/// let plaintext = "The cake is a lie".as_bytes();
/// let pass = "My secret passphrase".as_bytes();
/// let cryptor = RingCryptor::new();
///
/// // The user can create this buffer beforehand.
/// let meta = Metadata::generate_for_passphrase(plaintext.len());
/// let (mut _buf, meta_size) = meta.to_buf();
/// let mut buf = &mut _buf[meta_size..];
/// buf[..plaintext.len()].copy_from_slice(plaintext);
///
/// // The user should derive the key from the passphrase.
/// let key = RingCryptor::derive_key(&meta, pass)?;
///
/// // These methods will not perform any allocation, and will encrypt/decrypt
/// // the data in place.
/// cryptor.seal_in_place(&meta, &key, buf)?;
/// cryptor.open_in_place(&meta, &key, buf)?;
/// assert_eq!(&buf[..plaintext.len()], plaintext);
///
/// # use tindercrypt::errors;
/// # Ok::<(), errors::Error>(())
/// ```
///
/// The user is also free to specify their own metadata for the encryption
/// process, or use additional associated data (AAD). In the following example,
/// the user instructs the cryptor to derive a symmetric key with 10 million
/// PBKDF2 iterations, use the ChaCha20-Poly1305 encryption algorithm and bind
/// the ciphertext with some AAD:
///
/// ```
/// use tindercrypt::metadata;
/// use tindercrypt::cryptors::RingCryptor;
///
/// let plaintext = "The cake is a lie".as_bytes();
/// let pass = "My secret passphrase".as_bytes();
/// let aad = "My encryption context".as_bytes();
/// let cryptor = RingCryptor::new().with_aad(aad); // Set the AAD.
///
/// // Create the Metadata struct.
/// let mut key_deriv_meta = metadata::KeyDerivationMetadata::generate();
/// key_deriv_meta.iterations = 10000000; // 10 million PBKDF2 iterations
/// # // ... but for the tests, lower the number of iterations.
/// # key_deriv_meta.iterations = 1;
/// let mut key_deriv_algo = metadata::KeyDerivationAlgorithm::PBKDF2(key_deriv_meta);
/// let enc_meta = metadata::EncryptionMetadata::generate();
/// let enc_algo = metadata::EncryptionAlgorithm::ChaCha20Poly1305(enc_meta);
/// let meta = metadata::Metadata::new(key_deriv_algo, enc_algo, plaintext.len());
///
/// // Serialize the Metadata struct into a buffer and copy the plaintext in it.
/// let (mut buf, meta_size) = meta.to_buf();
/// buf[meta_size..meta_size + plaintext.len()].copy_from_slice(&plaintext);
///
/// // Derive the key from the passphrase.
/// let key = RingCryptor::derive_key(&meta, pass)?;
///
/// // Encrypt and decrypt the data.
/// let ciphertext = cryptor.seal_with_meta(&meta, &key, &mut buf[meta_size..])?;
/// assert_eq!(cryptor.open(pass, &ciphertext)?, plaintext);
///
/// # use tindercrypt::errors;
/// # Ok::<(), errors::Error>(())
/// ```
///
/// [metadata]: ../metadata/index.html
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct RingCryptor<'a> {
    aad: &'a [u8],
}

impl<'a> RingCryptor<'a> {
    /// Create a new cryptor instance.
    pub fn new() -> Self {
        Self { aad: &[] }
    }

    /// Specify the additional associated data (AAD) to be used.
    ///
    /// Normally, when encrypting/decrypting a data buffer, the user needs to
    /// provide just a key. In some cases though, especially when the same key
    /// is used multiple times, we may want to ensure that the data
    /// we're decrypting are the expected ones.
    ///
    /// By specifying associated data during the encryption, we bind them to
    /// the ciphertext. The associated data are not stored with the ciphertext,
    /// but are necessary to decrypt the data. This way, attempts to
    /// "cut-and-paste" a valid ciphertext into a different context are
    /// detected and rejected.
    pub fn with_aad(self, aad: &'a [u8]) -> Self {
        Self { aad }
    }

    /// Get the proper key size for the encryption algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use tindercrypt::metadata;
    /// use tindercrypt::cryptors::RingCryptor;
    ///
    /// let enc_meta = metadata::EncryptionMetadata::generate();
    /// let enc_algo = metadata::EncryptionAlgorithm::ChaCha20Poly1305(enc_meta);
    ///
    /// // The ChaCha20 cipher requires a 256-bit key.
    /// assert_eq!(RingCryptor::get_key_size(&enc_algo), 32);
    /// ```
    pub fn get_key_size(enc_algo: &metadata::EncryptionAlgorithm) -> usize {
        match enc_algo {
            metadata::EncryptionAlgorithm::AES256GCM(_) => {
                ring::aead::AES_256_GCM.key_len()
            }
            metadata::EncryptionAlgorithm::ChaCha20Poly1305(_) => {
                ring::aead::CHACHA20_POLY1305.key_len()
            }
        }
    }

    /// Verify that the key size matches the encryption algorithm.
    ///
    /// Keys of different size will fail verification with
    /// [`errors::Error::KeySizeMismatch`].
    ///
    /// # Examples
    ///
    /// ```
    /// use tindercrypt::metadata;
    /// use tindercrypt::errors::Error;
    /// use tindercrypt::cryptors::RingCryptor;
    ///
    /// let enc_meta = metadata::EncryptionMetadata::generate();
    /// let enc_algo = metadata::EncryptionAlgorithm::ChaCha20Poly1305(enc_meta);
    ///
    /// // The ChaCha20 cipher requires a 256-bit key.
    /// let key = vec![9u8; 32];
    /// assert_eq!(RingCryptor::verify_key_size(&enc_algo, &[]), Err(Error::KeySizeMismatch));
    /// assert_eq!(RingCryptor::verify_key_size(&enc_algo, &key), Ok(()));
    /// ```
    pub fn verify_key_size(
        enc_algo: &metadata::EncryptionAlgorithm,
        key: &[u8],
    ) -> Result<(), errors::Error> {
        if key.len() != Self::get_key_size(enc_algo) {
            return Err(errors::Error::KeySizeMismatch);
        }
        Ok(())
    }

    fn _get_enc_info(
        &self,
        enc_algo: &metadata::EncryptionAlgorithm,
    ) -> (&'static ring::aead::Algorithm, [u8; aead::NONCE_SIZE]) {
        match enc_algo {
            metadata::EncryptionAlgorithm::AES256GCM(meta) => {
                (&ring::aead::AES_256_GCM, meta.nonce)
            }
            metadata::EncryptionAlgorithm::ChaCha20Poly1305(meta) => {
                (&ring::aead::CHACHA20_POLY1305, meta.nonce)
            }
        }
    }

    /// Derive a key from the provided secret and metadata, with no allocation.
    ///
    /// This function is useful for those that want to manage the key buffer
    /// themselves, either for performance or security reasons.
    ///
    /// Depending on the key derivation algorithm in the metadata, this
    /// function will derive a key from `secret` and store it into `key`. If
    /// the key derivation algorithm is
    /// [`metadata::KeyDerivationAlgorithm::None`], then the `secret` will just
    /// be copied to `key`.
    ///
    /// If the key buffer does not match the required key size, this function
    /// will return an error (see [`RingCryptor::verify_key_size`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use tindercrypt::metadata;
    /// use tindercrypt::errors::Error;
    /// use tindercrypt::cryptors::RingCryptor;
    ///
    /// let meta = metadata::Metadata::generate_for_passphrase(0);
    ///
    /// let pass = "My secret passphrase".as_bytes();
    /// let mut key = [0u8; 32];
    ///
    /// assert_eq!(RingCryptor::derive_key_no_alloc(&meta, &pass, &mut key), Ok(()));
    /// ```
    pub fn derive_key_no_alloc(
        meta: &metadata::Metadata,
        secret: &[u8],
        key: &mut [u8],
    ) -> Result<(), errors::Error> {
        Self::verify_key_size(&meta.enc_algo, key)?;
        match meta.key_deriv_algo {
            metadata::KeyDerivationAlgorithm::None => {
                Self::verify_key_size(&meta.enc_algo, secret)?;
                key.copy_from_slice(secret);
            }
            metadata::KeyDerivationAlgorithm::PBKDF2(meta) => {
                let algo = match meta.hash_fn {
                    metadata::HashFunction::SHA256 => {
                        ring::pbkdf2::PBKDF2_HMAC_SHA256
                    }
                    metadata::HashFunction::SHA384 => {
                        ring::pbkdf2::PBKDF2_HMAC_SHA384
                    }
                    metadata::HashFunction::SHA512 => {
                        ring::pbkdf2::PBKDF2_HMAC_SHA512
                    }
                };
                pbkdf2::derive_key(
                    algo,
                    meta.iterations,
                    &meta.salt,
                    secret,
                    key,
                )?;
            }
        };
        Ok(())
    }

    /// Derive a key from the provided secret and metadata.
    ///
    /// This function is useful for those that want an easy and safe way to
    /// derive a key. Compared to [`RingCryptor::derive_key_no_alloc`], it:
    ///
    /// * Allocates and returns a key buffer with the proper size.
    /// * Ensures that the key will be safely erased from memory after use,
    ///   with the help of the [`zeroize`] crate.
    ///
    /// # Examples
    ///
    /// ```
    /// use tindercrypt::metadata;
    /// use tindercrypt::errors::Error;
    /// use tindercrypt::cryptors::RingCryptor;
    ///
    /// let meta = metadata::Metadata::generate_for_passphrase(0);
    ///
    /// let pass = "My secret passphrase".as_bytes();
    /// let key = RingCryptor::derive_key(&meta, &pass)?;
    ///
    /// # use tindercrypt::errors;
    /// # Ok::<(), errors::Error>(())
    /// ```
    ///
    /// [`zeroize`]: https://docs.rs/zeroize
    pub fn derive_key(
        meta: &metadata::Metadata,
        secret: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, errors::Error> {
        let key_size = Self::get_key_size(&meta.enc_algo);
        let mut key = zeroize::Zeroizing::new(vec![0u8; key_size]);
        Self::derive_key_no_alloc(meta, secret, &mut key)?;
        Ok(key)
    }

    /// Encrypt (seal) the data buffer in place.
    ///
    /// This method gets the metadata necessary from the `EncryptionAlgorithm`
    /// enum and calls the respective AEAD wrapper.
    fn _seal_in_place(
        &self,
        enc_algo: &metadata::EncryptionAlgorithm,
        key: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, errors::Error> {
        Self::verify_key_size(enc_algo, key)?;
        let (algo, nonce) = self._get_enc_info(enc_algo);
        aead::seal_in_place(algo, nonce, self.aad, key, buf)
    }

    /// Decrypt (open) the data buffer in place.
    ///
    /// This method gets the metadata necessary from the `EncryptionAlgorithm`
    /// enum and calls the respective AEAD wrapper.
    fn _open_in_place(
        &self,
        enc_algo: &metadata::EncryptionAlgorithm,
        key: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, errors::Error> {
        Self::verify_key_size(enc_algo, key)?;
        let (algo, nonce) = self._get_enc_info(enc_algo);
        aead::open_in_place(algo, nonce, self.aad, key, buf)
    }

    /// Encrypt (seal) the data buffer in place.
    ///
    /// This method accepts a metadata instance, a key and a data buffer, that
    /// contains the plaintext and enough space for the tag. Key derivation, if
    /// required, must be performed by the user beforehand (see
    /// [`RingCryptor::derive_key`]).
    ///
    /// This method seals the data in place, using the encryption algorithm
    /// specified in the metadata. It is much faster than the `seal_with_*`
    /// methods that this cryptor provides, since it doesn't perform any
    /// allocations. The drawback is that the plaintext is not preserved and
    /// that the user must create the proper buffer layout beforehand.
    pub fn seal_in_place(
        &self,
        meta: &metadata::Metadata,
        key: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, errors::Error> {
        self._seal_in_place(&meta.enc_algo, &key, buf)
    }

    /// Encrypt (seal) the data buffer using the provided metadata.
    ///
    /// This method accepts a metadata instance, a key and the plaintext. Key
    /// derivation, if required, must be performed by the user beforehand (see
    /// [`RingCryptor::derive_key`]).
    ///
    /// This method serializes the metadata instance to a buffer, copies the
    /// plaintext in it and then seals it in place. This way, the plaintext is
    /// preserved, at the cost of an extra copy.
    pub fn seal_with_meta(
        &self,
        meta: &metadata::Metadata,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, errors::Error> {
        // FIXME: Do we need so many `mut` here?
        let (mut buf, meta_size) = meta.to_buf();
        let mut ciphertext = &mut buf[meta_size..];

        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        let _ = self.seal_in_place(meta, key, &mut ciphertext)?;
        Ok(buf)
    }

    /// Encrypt (seal) the data buffer using a symmetric key.
    ///
    /// This method accepts a metadata instance, a symmetric key and the
    /// plaintext.
    ///
    /// It generates a metadata instance and then uses the `.seal_with_meta()`
    /// method to seal the data. The plaintext will be preserved, at the cost
    /// of an extra copy.
    pub fn seal_with_key(
        &self,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, errors::Error> {
        let meta = metadata::Metadata::generate_for_key(plaintext.len());
        self.seal_with_meta(&meta, key, plaintext)
    }

    /// Encrypt (seal) the data buffer using a passphrase.
    ///
    /// This method accepts a metadata instance, a passphrase and the
    /// plaintext.
    ///
    /// It generates a metadata instance with the proper key derivation
    /// algorithm, derives the key from the passphrase, and then uses the
    /// `.seal_with_meta()` method to seal the data. The plaintext will be
    /// preserved, at the cost of an extra copy.
    pub fn seal_with_passphrase(
        &self,
        pass: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, errors::Error> {
        let meta =
            metadata::Metadata::generate_for_passphrase(plaintext.len());
        let key = Self::derive_key(&meta, pass)?;
        self.seal_with_meta(&meta, &key, plaintext)
    }

    /// Decrypt (open) the data buffer in place.
    ///
    /// This method accepts a metadata instance, a key and a data buffer, that
    /// contains the plaintext and enough space for the tag. Key derivation, if
    /// required, must be performed by the user beforehand (see
    /// [`RingCryptor::derive_key`]).
    ///
    /// This method opens the data in place, using the encryption algorithm
    /// specified in the metadata. It is much faster than the other `open*`
    /// methods that this cryptor provides, since it doesn't perform any
    /// allocations. The drawback is that the ciphertext is not preserved.
    pub fn open_in_place(
        &self,
        meta: &metadata::Metadata,
        key: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, errors::Error> {
        self._open_in_place(&meta.enc_algo, &key, buf)
    }

    /// Decrypt (open) the data buffer using the provided metadata.
    ///
    /// This method accepts a metadata instance, a key and the ciphertext. Key
    /// derivation, if required, must be performed by the user beforehand (see
    /// [`RingCryptor::derive_key`]).
    ///
    /// This method copies the ciphertext to a new buffer and decrypts (opens)
    /// it in place. Then, it returns the buffer with the plaintext. This way,
    /// the ciphertext is preserved, at the cost of an extra copy.
    ///
    /// **Note:** By "ciphertext" we don't refer to the whole buffer that the
    /// `seal_*` methods produce. We refer to the part with the encrypted
    /// payload, which does not include the metadata. For more info on how to
    /// extract this part, see the examples in the [`RingCryptor`]
    /// documentation.
    pub fn open_with_meta(
        &self,
        meta: &metadata::Metadata,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, errors::Error> {
        let mut buf = ciphertext.to_vec();
        let size = self.open_in_place(meta, key, &mut buf)?;
        let _ = buf.drain(size..);
        Ok(buf)
    }

    /// Decrypt (open) the data buffer.
    ///
    /// This method accepts a secret value (either a key or a passphrase) and
    /// a data buffer that contains the serialized metadata and the ciphertext.
    ///
    /// It deserializes the metadata and extracts the ciphertext from the
    /// buffer. Depending on the key derivation algorithm, this method may
    /// derive a key from the provided passpphrase using the values in the
    /// deserialized metadata. Then, it uses `.open_with_meta()` to decrypt the
    /// ciphertext.  The buffer will be preserved, at the cost of an extra
    /// copy.
    pub fn open(
        &self,
        secret: &[u8],
        buf: &[u8],
    ) -> Result<Vec<u8>, errors::Error> {
        let (meta, meta_size) = metadata::Metadata::from_buf(buf)?;
        let ciphertext = &buf[meta_size..];
        let key = Self::derive_key(&meta, secret)?;
        self.open_with_meta(&meta, &key, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simplified options for the key derivation algorithm, used only in the
    /// tests.
    enum KeyOpts {
        None,
        PBKDF2,
    }

    /// Simplified options for the encryption algorithm, used only in the
    /// tests.
    enum EncOpts {
        AES,
        ChaCha,
    }

    /// Generate a metadata struct for the tests, based on the selected key
    /// derivation and encryption algorithms.
    fn generate_meta(
        size: usize,
        key_opts: KeyOpts,
        enc_opts: EncOpts,
    ) -> metadata::Metadata {
        // Key derivation algorithm.
        let key_algo = match key_opts {
            KeyOpts::None => metadata::KeyDerivationAlgorithm::None,
            KeyOpts::PBKDF2 => {
                let mut key_deriv_meta =
                    metadata::KeyDerivationMetadata::generate();
                key_deriv_meta.iterations = 1;
                metadata::KeyDerivationAlgorithm::PBKDF2(key_deriv_meta)
            }
        };

        // Encryption algorithm.
        let enc_meta = metadata::EncryptionMetadata::generate();
        let enc_algo = match enc_opts {
            EncOpts::AES => metadata::EncryptionAlgorithm::AES256GCM(enc_meta),
            EncOpts::ChaCha => {
                metadata::EncryptionAlgorithm::ChaCha20Poly1305(enc_meta)
            }
        };

        metadata::Metadata::new(key_algo, enc_algo, size)
    }

    #[test]
    fn test_derive_key() {
        let key_err = Err(errors::Error::KeySizeMismatch);
        let pass_err = Err(errors::Error::PassphraseTooSmall);

        // Test 1 - No key derivation.
        //
        // Ensure that wrong key sizes are rejected. Also, check that the
        // provided secret gets copied to the key as is.
        let meta = metadata::Metadata::generate_for_key(0);
        let key_size = RingCryptor::get_key_size(&meta.enc_algo);
        let secret = vec![9u8; key_size];
        let mut key = vec![0u8; key_size];

        let res = RingCryptor::derive_key_no_alloc(&meta, &[], &mut key);
        assert_eq!(res, key_err);
        let res = RingCryptor::derive_key_no_alloc(&meta, &secret, &mut []);
        assert_eq!(res, key_err);
        let res = RingCryptor::derive_key_no_alloc(&meta, &secret, &mut key);
        assert_eq!(res, Ok(()));
        assert_eq!(secret, key);

        // Test 2 - PBKDF2 key derivation.
        //
        // Ensure that wrong key sizes are rejected. Also, check that the
        // derived key does not match the secret and is not empty.
        let meta = metadata::Metadata::generate_for_passphrase(0);
        let key_size = RingCryptor::get_key_size(&meta.enc_algo);
        let secret = vec![9u8; key_size];
        let mut key = vec![0u8; key_size];

        let res = RingCryptor::derive_key_no_alloc(&meta, &secret, &mut []);
        assert_eq!(res, key_err);
        let res = RingCryptor::derive_key_no_alloc(&meta, &[], &mut key);
        assert_eq!(res, pass_err);
        let res = RingCryptor::derive_key_no_alloc(&meta, &secret, &mut key);
        assert_eq!(res, Ok(()));
        assert!(key != secret);
        assert!(key != vec![0u8; key_size]);
    }

    #[test]
    fn test_seal_open_in_place() {
        // Create some initial data.
        let plaintext = "The cake is a lie".as_bytes();
        let aad = "My context".as_bytes();

        let buf_err = Err(errors::Error::BufferTooSmall);
        let dec_err = Err(errors::Error::DecryptionError);
        let key_err = Err(errors::Error::KeySizeMismatch);

        // Create two cryptors, one with additional associated data and one
        // without.
        let cryptor = RingCryptor::new();
        let cryptor_with_aad = RingCryptor::new().with_aad(aad);

        // Use the following types of metadata and keys for the test:
        //
        // PBKDF2 key derivation and AES-256-GCM encryption, with passphrase.
        let meta1 =
            generate_meta(plaintext.len(), KeyOpts::PBKDF2, EncOpts::AES);
        let secret1 = "My passphrase 1".as_bytes();
        let key_size = RingCryptor::get_key_size(&meta1.enc_algo);
        let mut key1 = vec![0u8; key_size];
        RingCryptor::derive_key_no_alloc(&meta1, &secret1, &mut key1).unwrap();

        // PBKDF2 key derivation and ChaCha20-Poly1305 encryption, with
        // passphrase.
        let meta2 =
            generate_meta(plaintext.len(), KeyOpts::PBKDF2, EncOpts::ChaCha);
        let key2 = key1.clone();

        // No key derivation and AES-256-GCM encryption, with symmetric key.
        let meta3 =
            generate_meta(plaintext.len(), KeyOpts::None, EncOpts::AES);
        let key3 = vec![9u8; ring::aead::AES_256_GCM.key_len()];

        // No key derivation and ChaCha20-Poly1305 encryption, with symmetric
        // key.
        let meta4 =
            generate_meta(plaintext.len(), KeyOpts::None, EncOpts::ChaCha);
        let key4 = key3.clone();

        // Test that the encryption operation returns the expected errors for
        // each type of user mistake and metadata configuration.
        //
        // No buffer.
        for (meta, key) in &[
            (meta1, &key1),
            (meta2, &key2),
            (meta3, &key3),
            (meta4, &key4),
        ] {
            let err = cryptor.seal_in_place(&meta, key, &mut []);
            assert_eq!(buf_err, err);
        }

        // Wrong key size.
        for meta in &[meta1, meta2, meta3, meta4] {
            let err = cryptor.seal_in_place(&meta, &[], &mut []);
            assert_eq!(key_err, err);
            let err = cryptor.seal_in_place(&meta, &secret1, &mut []);
            assert_eq!(key_err, err);
        }

        // Test that the encryption operation succeeds.
        let mut ciphertexts = Vec::new();
        for (meta, key) in &[
            (meta1, &key1),
            (meta2, &key2),
            (meta3, &key3),
            (meta4, &key4),
        ] {
            let (mut buf, meta_size) = meta.to_buf();
            let mut ciphertext = &mut buf[meta_size..];
            ciphertext[..plaintext.len()].copy_from_slice(plaintext);
            let res = cryptor.seal_in_place(&meta, key, &mut ciphertext);
            assert_eq!(res, Ok(plaintext.len()));

            let _ = buf.drain(..meta_size);
            ciphertexts.push(buf);
        }

        // Test that the decryption operation returns the expected errors for
        // each type of user mistake and metadata configuration.
        //
        // No buffer.
        for (meta, key) in &[
            (meta1, &key1),
            (meta2, &key2),
            (meta3, &key3),
            (meta4, &key4),
        ] {
            let err = cryptor.open_in_place(&meta, key, &mut []);
            assert_eq!(buf_err, err);
        }

        // No key.
        for meta in &[meta1, meta2, meta3, meta4] {
            let err = cryptor.open_in_place(&meta, &[], &mut []);
            assert_eq!(key_err, err);
        }

        // Test that the decryption operation returns a decryption error when
        // the keys/passphrases are wrong.
        let wrong_key1 = vec![1u8; ring::aead::AES_256_GCM.key_len()];
        let wrong_key2 = vec![2u8; ring::aead::CHACHA20_POLY1305.key_len()];
        for (meta, wrong_key, buf) in &[
            (meta1, &wrong_key1, &ciphertexts[0]),
            (meta2, &wrong_key2, &ciphertexts[1]),
            (meta3, &wrong_key1, &ciphertexts[2]),
            (meta4, &wrong_key2, &ciphertexts[3]),
        ] {
            let mut buf = buf.to_vec();
            let err = cryptor.open_in_place(&meta, wrong_key, &mut buf);
            assert_eq!(dec_err, err);
        }

        // Test that the decryption operation returns a decryption error when
        // the additional associated data mismatch.
        for (meta, key, buf) in &mut [
            (meta1, &key1, &ciphertexts[0]),
            (meta2, &key2, &ciphertexts[1]),
            (meta3, &key3, &ciphertexts[2]),
            (meta4, &key4, &ciphertexts[3]),
        ] {
            let mut buf = buf.to_vec();
            let err = cryptor_with_aad.open_in_place(&meta, key, &mut buf);
            assert_eq!(dec_err, err);
        }

        // Test that the decryption operation returns a decryption error when
        // the encryption algorithms are incorrect.
        for (meta, key, buf) in &[
            (meta1, &key1, &ciphertexts[1]),
            (meta2, &key2, &ciphertexts[0]),
            (meta3, &key3, &ciphertexts[3]),
            (meta4, &key4, &ciphertexts[2]),
        ] {
            let mut buf = buf.to_vec();
            let err = cryptor.open_in_place(&meta, key, &mut buf);
            assert_eq!(dec_err, err);
        }

        // Test that the decryption operation returns a decryption error when
        // the key derivation / encryption algorithms match, but their metadata
        // mismatch.
        let wrong_meta1 =
            generate_meta(plaintext.len(), KeyOpts::PBKDF2, EncOpts::AES);
        let wrong_meta2 =
            generate_meta(plaintext.len(), KeyOpts::PBKDF2, EncOpts::ChaCha);
        let wrong_meta3 =
            generate_meta(plaintext.len(), KeyOpts::None, EncOpts::AES);
        let wrong_meta4 =
            generate_meta(plaintext.len(), KeyOpts::None, EncOpts::ChaCha);
        for (wrong_meta, key, buf) in &mut [
            (wrong_meta1, &key1, &ciphertexts[0]),
            (wrong_meta2, &key2, &ciphertexts[1]),
            (wrong_meta3, &key3, &ciphertexts[2]),
            (wrong_meta4, &key4, &ciphertexts[3]),
        ] {
            let mut buf = buf.to_vec();
            let err = cryptor.open_in_place(&wrong_meta, key, &mut buf);
            assert_eq!(dec_err, err);
        }

        // Test a successful decryption operation.
        for (meta, key, buf) in &[
            (meta1, &key1, &ciphertexts[0]),
            (meta2, &key2, &ciphertexts[1]),
            (meta3, &key3, &ciphertexts[2]),
            (meta4, &key4, &ciphertexts[3]),
        ] {
            let mut buf = buf.to_vec();
            let res = cryptor.open_in_place(&meta, key, &mut buf);
            assert_eq!(res, Ok(plaintext.len()));
            assert_eq!(&buf[..plaintext.len()], plaintext);
        }
    }

    #[test]
    fn test_seal_open() {
        let data = vec![9u8; 9];

        let cryptor = RingCryptor::new().with_aad("death".as_bytes());
        let res = cryptor.seal_with_passphrase("pass".as_bytes(), &data);
        assert!(res.is_ok());

        let res = cryptor.open("pass".as_bytes(), &res.unwrap());
        assert!(res.is_ok());
        assert_eq!(data, res.unwrap());
    }
}

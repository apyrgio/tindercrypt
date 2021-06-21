//! # Tindercrypt Metadata
//!
//! The process of data encryption has various metadata, such as salts, nonces,
//! algorithms, etc. The purpose of this module to generate and handle them
//! properly.
//!
//! Currently, Tindercrypt understands the following types of metadata:
//!
//! * **Key derivation metadata:** If a user chooses to encrypt their data with
//!   a passphrase, they need to use a key derivation algorithm in order to
//!   create a key with a specific size. For instance, PBKDF2 requires a salt,
//!   a hash function and a number of iterations. The available key derivation
//!   algorithms and their associated metadata are covered in
//!   [`KeyDerivationAlgorithm`]
//! * **Encryption metadata:** The encryption algorithms that Tindercrypt
//!   currently supports require a unique nonce and optionally supports
//!   [associated data]. The available algorithms and their metadata are
//!   covered in [`EncryptionAlgorithm`].
//!
//! While the user is free to choose their own salts and nonces, in most cases
//! they should just use the `::generate()` constructor of the respective
//! metadata types.
//!
//! Tindercrypt provides a container where the above metadata are stored, the
//! [`Metadata`] struct. This struct holds all the encryption context and is
//! provided to cryptors when encrypting/decrypting data. Also, this struct is
//! serialized and prepended to the ciphertext, when encrypting the data. See
//! the [Serialization] section for more info.
//!
//! ## Serialization
//!
//! Tindercrypt uses [Protocol Buffers] to handle the (de)serialization of the
//! [`Metadata`] struct. There are three reasons why we chose them instead of a
//! custom wire format:
//!
//! * **Security:** An attacker with access to the ciphertext cannot create a
//!   header that will cause arbitrary code execution. Protocol Buffers are
//!   designed to thwart such attacks, and we use a Rust library
//!   ([`rust-protobuf`]) for the implementation details.
//! * **Extensibility:** If in the future we decide that we want to support an
//!   extra algorithm, we can do so easily, without breaking the parsing of
//!   existing serialized data.
//! * **Interoperability:** Anyone can deserialize the metadata header, as long
//!   as they use the protobuf definitions of this library. Protocol buffers
//!   offer bindings for most common languages.
//!
//! For each metadata type defined in this module, there is a protobuf
//! definition with almost the same fields. The generated Rust code is
//! available in the [`proto::metadata`] module.
//!
//! In a nutshell, the serialization process is the following:
//!
//! * Convert a [`Metadata`] struct to a [`proto::metadata::Metadata`] message.
//! * Serialize the [`proto::metadata::Metadata`] message to a `Vec<u8>`
//!   buffer.
//! * Extend the buffer to also hold the ciphertext.
//! * Return the created buffer and the size of the serialized metadata. The
//!   latter can be used to know where the ciphertext section begins within the
//!   buffer.
//!
//! The deserialization process is a bit more involved, as we must also check
//! the integrity of the metadata:
//!
//! * Deserialize the buffer header into a [`proto::metadata::Metadata`]
//!   message. Failure to do so means that the buffer does not contain such a
//!   header, or that the header is corrupted.
//! * Convert the [`proto::metadata::Metadata`] message into a [`Metadata`]
//!   struct. Failure to do so means that the buffer contains a structurally
//!   valid metadata header, but its fields contain invalid values.
//! * Return the created [`Metadata`] struct and the size of the serialized
//!   metadata.
//!
//! [`KeyDerivationAlgorithm`]: enum.KeyDerivationAlgorithm.html
//! [`EncryptionAlgorithm`]: enum.EncryptionAlgorithm.html
//! [`Metadata`]: struct.Metadata.html
//! [Protocol Buffers]: https://developers.google.com/protocol-buffers/
//! [`rust-protobuf`]: https://github.com/stepancheg/rust-protobuf
//! [`proto::metadata`]: ../proto/metadata/index.html
//! [`proto::metadata::Metadata`]: ../proto/metadata/struct.Metadata.html
//! [Serialization]: #serialization
//! [associated data]: https://en.wikipedia.org/wiki/Authenticated_encryption

use crate::proto::metadata as pmeta;
use crate::{errors, rand};
use protobuf::Message;

/// The size of the nonces for the encryption algorithms provided by Ring.
///
/// We use a constant size of 12 bytes for the nonces, because it's the
/// recommended size by IETF [^ietf], and because the Ring library does not
/// accept any other size.
///
/// [^ietf]: From <https://tools.ietf.org/html/rfc5084#section-3.2>:
///          _A length of 12 octets is RECOMMENDED._
pub const RING_NONCE_SIZE: usize = 12;

/// The size of the salt values for the PBKDF2 key derivation algorithm.
///
/// We use a constant size of 32 bytes for the salt values, because the
/// general recommendation is that salts should be globally unique.
pub const PBKDF2_SALT_SIZE: usize = 32;

/// The default number of iterations for the PBKDF2 key derivation algorithm.
///
/// We use a constant number of 100,000 iterations. As of 2019, this number
/// seems to be commonly suggested, and is used in various projects, such as
/// the Borg backup project ([issue]) and 1Password ([blog]). While not
/// ideal, from a strict security standpoint, raising it higher would make it
/// less tolerable in low-end devices, and wouldn't offer better security than
/// a more modern KDF, such as `scrypt` or `argon2`.
///
/// To understand the performance gap between different devices, here's a quick
/// run of `cryptsetup benchmark` for the PBKDF2-sha256 algorithm, in a
/// mid-end and low-end device:
///
/// * Mid 2010 i7 CPU: ~1,800,000 iterations per second for 256-bit key
/// * Raspberry Pi 3 Model B: ~270,000 iterations per second for 256-bit key
///
/// With 100,000 iterations, a mid-end device would require roughly 55ms to
/// create a key, while a low-end device would require roughly 370ms.
///
/// [issue]: https://github.com/borgbackup/borg/issues/77
/// [blog]: https://support.1password.com/pbkdf2/
pub const PBKDF2_DEFAULT_ITERATIONS: usize = 100000;

/// The default hash function for the PBKDF2 key derivation algorithm.
///
/// We use the SHA-256 hash function since we want to create 256-bit keys, and
/// because it's generally better if the output of the HMAC function matches
/// the length of the desired key [^pbkdf2-design-flaw].
///
/// [^pbkdf2-design-flaw]: <https://www.chosenplaintext.ca/2015/10/08/pbkdf2-design-flaw.html>
pub const PBKDF2_DEFAULT_HASH_FN: HashFunction = HashFunction::SHA256;

/// The hash functions that this library supports.
///
/// Currently, these hash functions dictate the HMAC function that PBKDF2 will
/// use.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HashFunction {
    SHA256,
    SHA384,
    SHA512,
}

impl HashFunction {
    /// Create a hash function from the respective protobuf-generated enum.
    ///
    /// This method may return an error, if the protobuf-generated enum is
    /// invalid.
    pub fn from_proto(
        proto_hash_fn: pmeta::HashFunction,
    ) -> Result<Self, errors::Error> {
        match proto_hash_fn {
            pmeta::HashFunction::HASH_FUNCTION_INVALID => {
                Err(errors::Error::MetadataInvalid)
            }
            pmeta::HashFunction::HASH_FUNCTION_SHA256 => {
                Ok(HashFunction::SHA256)
            }
            pmeta::HashFunction::HASH_FUNCTION_SHA384 => {
                Ok(HashFunction::SHA384)
            }
            pmeta::HashFunction::HASH_FUNCTION_SHA512 => {
                Ok(HashFunction::SHA512)
            }
        }
    }

    /// Convert a hash function to the respective protobuf-generated enum.
    pub fn to_proto(&self) -> pmeta::HashFunction {
        match self {
            HashFunction::SHA256 => pmeta::HashFunction::HASH_FUNCTION_SHA256,
            HashFunction::SHA384 => pmeta::HashFunction::HASH_FUNCTION_SHA384,
            HashFunction::SHA512 => pmeta::HashFunction::HASH_FUNCTION_SHA512,
        }
    }
}

/// The metadata that can be used for the key derivation process.
///
/// Currently, these metadata map 1-1 to the metadata necessary for the PBKDF2
/// algorithm.
///
/// # Examples
///
/// ```
/// use tindercrypt::metadata::{HashFunction, KeyDerivationMetadata};
///
/// // Generate a struct instance for the key derivation metadata. The default
/// // is to choose an HMAC function based on SHA-256, 100,000 iterations of
/// // PBKDF2 and a unique salt.
/// let key_meta1 = KeyDerivationMetadata::generate();
/// assert_eq!(key_meta1.hash_fn, HashFunction::SHA256);
/// assert_eq!(key_meta1.iterations, 100000);
///
/// // Generate a second struct instance. The salt should be unique.
/// let key_meta2 = KeyDerivationMetadata::generate();
/// assert_eq!(key_meta1.hash_fn, HashFunction::SHA256);
/// assert_eq!(key_meta1.iterations, 100000);
/// assert_ne!(key_meta1.salt, key_meta2.salt);
/// ```
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeyDerivationMetadata {
    /// The hash function that is used as the basis for the computational work.
    pub hash_fn: HashFunction,
    /// The number of iterations for the key derivation algorithm.
    pub iterations: usize,
    /// A unique value that is used to create different keys from the same
    /// passphrase.
    pub salt: [u8; PBKDF2_SALT_SIZE],
}

impl KeyDerivationMetadata {
    /// Create the key derivation metadata from user-provided values.
    ///
    /// This method should be used only when the user wants to explicitly set
    /// a specific value. Else, it's better to use `::generate()`.
    pub fn new(
        hash_fn: HashFunction,
        iterations: usize,
        salt: [u8; PBKDF2_SALT_SIZE],
    ) -> Self {
        Self {
            hash_fn,
            iterations,
            salt,
        }
    }

    /// Generate key derivation metadata.
    pub fn generate() -> Self {
        let mut salt = [0u8; PBKDF2_SALT_SIZE];
        rand::fill_buf(&mut salt);
        Self::new(PBKDF2_DEFAULT_HASH_FN, PBKDF2_DEFAULT_ITERATIONS, salt)
    }
}

/// The key derivation algorithm that will be used.
///
/// ## Examples
///
/// ```
/// use tindercrypt::metadata::{KeyDerivationMetadata, KeyDerivationAlgorithm};
///
/// // Create a PBKDF2 key derivation algorithm.
/// let key_meta = KeyDerivationMetadata::generate();
/// let key_algo_pbkdf2 = KeyDerivationAlgorithm::PBKDF2(key_meta);
///
/// // Create a no-op key derivation algorithm.
/// let key_algo_none = KeyDerivationAlgorithm::None;
/// ```
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyDerivationAlgorithm {
    /// No key derivation.
    None,
    /// Derive a key using the PBKDF2 algorithm.
    PBKDF2(KeyDerivationMetadata),
}

impl KeyDerivationAlgorithm {
    /// Create a key derivation algorithm from the respective
    /// protobuf-generated metadata.
    ///
    /// This method may return an error, if the protobuf-generated metadata
    /// have invalid fields.
    pub fn from_proto(
        proto_meta: &pmeta::KeyDerivationMetadata,
    ) -> Result<Self, errors::Error> {
        let err = Err(errors::Error::MetadataInvalid);

        // Check if the defined key derivation algorithm is invalid. If it's
        // "None", then simply return it.
        match proto_meta.algo {
            pmeta::KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_INVALID => {
                return err;
            },
            pmeta::KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_NONE => {
                return Ok(KeyDerivationAlgorithm::None);
            },
            pmeta::KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_PBKDF2 => {
                ()
            },
        }

        // Check if the number of iterations is larger than 0.
        if proto_meta.iterations == 0 {
            return err;
        }
        let iterations = proto_meta.iterations as usize;

        // Convert the hash function to the expected enum.
        let hash_fn = HashFunction::from_proto(proto_meta.hash_fn)?;

        // Copy the salt to a fixed-size array. If the size is not the expected
        // one, return an error.
        if proto_meta.salt.len() != PBKDF2_SALT_SIZE {
            return err;
        }
        let mut salt = [0u8; PBKDF2_SALT_SIZE];
        salt.copy_from_slice(&proto_meta.salt);

        // Create the metadata object from the parsed values.
        let meta = KeyDerivationMetadata::new(hash_fn, iterations, salt);
        Ok(KeyDerivationAlgorithm::PBKDF2(meta))
    }

    /// Convert a key derivation algorithm to the respective protobuf-generated
    /// metadata.
    pub fn to_proto(&self) -> pmeta::KeyDerivationMetadata {
        let mut proto_meta = pmeta::KeyDerivationMetadata::new();
        let proto_none_algo =
            pmeta::KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_NONE;
        let proto_pbkdf2_algo =
            pmeta::KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_PBKDF2;

        let meta = match self {
            KeyDerivationAlgorithm::None => {
                proto_meta.algo = proto_none_algo;
                return proto_meta;
            }
            KeyDerivationAlgorithm::PBKDF2(meta) => meta,
        };

        proto_meta.algo = proto_pbkdf2_algo;
        proto_meta.iterations = meta.iterations as u64;
        proto_meta.hash_fn = meta.hash_fn.to_proto();
        proto_meta.salt = meta.salt.to_vec();
        proto_meta
    }
}

/// The metadata that can be used for the encryption process.
///
/// ## Examples
///
/// ```
/// use tindercrypt::metadata::EncryptionMetadata;
///
/// // Generate a struct instance for the encryption metadata.
/// let enc_meta1 = EncryptionMetadata::generate();
///
/// // Generate a second struct instance. The nonce should be different this time.
/// let enc_meta2 = EncryptionMetadata::generate();
/// assert_ne!(enc_meta1.nonce, enc_meta2.nonce);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EncryptionMetadata {
    /// The nonce value for the AEAD algorithms.
    ///
    /// Nonces are unique, 96-bit values, which are filled with random data.
    pub nonce: [u8; RING_NONCE_SIZE],
}

impl EncryptionMetadata {
    /// Create the encryption metadata from user-provided values.
    ///
    /// This method should be used only when the user wants to explicitly set
    /// a specific value. Else, it's better to use `::generate()`.
    pub fn new(nonce: [u8; RING_NONCE_SIZE]) -> Self {
        Self { nonce }
    }

    /// Generate encryption metadata.
    pub fn generate() -> Self {
        let mut nonce = [0u8; RING_NONCE_SIZE];
        rand::fill_buf(&mut nonce);
        Self::new(nonce)
    }
}

/// The encryption algorithm that will be used.
///
/// ## Examples
///
/// ```
/// use tindercrypt::metadata::{EncryptionMetadata, EncryptionAlgorithm};
///
/// let enc_meta = EncryptionMetadata::generate();
///
/// // Create an AES-256-GCM encryption algorithm.
/// let enc_algo_aes = EncryptionAlgorithm::AES256GCM(enc_meta);
///
/// // Create a ChaCha20-Poly1305 encryption algorithm.
/// let enc_algo_chacha = EncryptionAlgorithm::ChaCha20Poly1305(enc_meta);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EncryptionAlgorithm {
    /// The AES-256-GCM AEAD.
    AES256GCM(EncryptionMetadata),
    /// The ChaCha20-Poly1305 AEAD.
    ChaCha20Poly1305(EncryptionMetadata),
}

impl EncryptionAlgorithm {
    /// Create an encryption algorithm from the respective protobuf-generated
    /// metadata.
    ///
    /// This method may return an error, if the protobuf-generated metadata
    /// have invalid fields.
    pub fn from_proto(
        proto_meta: &pmeta::EncryptionMetadata,
    ) -> Result<Self, errors::Error> {
        let err = Err(errors::Error::MetadataInvalid);

        // Check if the defined encryption algorithm is invalid.
        match proto_meta.algo {
            pmeta::EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID => {
                return err
            }
            _ => (),
        };

        // Check if the nonce has the appropriate length and copy it.
        if proto_meta.nonce.len() != RING_NONCE_SIZE {
            return err;
        }
        let mut nonce = [0u8; RING_NONCE_SIZE];
        nonce.copy_from_slice(&proto_meta.nonce);

        // Create the metadata object from the parsed values.
        let meta = EncryptionMetadata::new(nonce);

        // Return the appropriate algorithm.
        match proto_meta.algo {
            pmeta::EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID => err,
            pmeta::EncryptionAlgorithm::ENCRYPTION_ALGORITHM_AES256GCM => {
                Ok(EncryptionAlgorithm::AES256GCM(meta))
            },
            pmeta::EncryptionAlgorithm::ENCRYPTION_ALGORITHM_CHACHA20_POLY1305 => {
                Ok(EncryptionAlgorithm::ChaCha20Poly1305(meta))
            }
        }
    }

    /// Convert an encryption algorithm to the respective protobuf-generated
    /// metadata.
    pub fn to_proto(&self) -> pmeta::EncryptionMetadata {
        let mut proto_meta = pmeta::EncryptionMetadata::new();
        let proto_aes_algo =
            pmeta::EncryptionAlgorithm::ENCRYPTION_ALGORITHM_AES256GCM;
        let proto_chacha_algo =
            pmeta::EncryptionAlgorithm::ENCRYPTION_ALGORITHM_CHACHA20_POLY1305;

        match self {
            EncryptionAlgorithm::AES256GCM(meta) => {
                proto_meta.algo = proto_aes_algo;
                proto_meta.nonce = meta.nonce.to_vec();
            }
            EncryptionAlgorithm::ChaCha20Poly1305(meta) => {
                proto_meta.algo = proto_chacha_algo;
                proto_meta.nonce = meta.nonce.to_vec();
            }
        };
        proto_meta
    }
}

/// The collection of all encryption-related metadata.
///
/// This struct holds all the metadata necessary for the encryption process.
/// The end product of the encryption will contain a serialized version of this
/// struct, so that it can be retrieved during decryption.
///
/// ## Examples
///
/// We can serialize the metadata to a buffer and then deserialize them again.
/// The reported size of the serialized metadata and their contents should be
/// the same in both cases:
///
/// ```
/// use tindercrypt::metadata::Metadata;
///
/// let data = "The cake is a lie";
/// let meta = Metadata::generate_for_passphrase(data.len());
/// let (buf, meta_size) = meta.to_buf();
/// assert_eq!(Metadata::from_buf(&buf)?, (meta, meta_size));
///
/// # use tindercrypt::errors;
/// # Ok::<(), errors::Error>(())
/// ```
///
/// We can also convert the metadata to and from the respective Protocol
/// Buffers message ([`proto::metadata::Metadata`]):
///
/// ```
/// use tindercrypt::metadata::Metadata;
///
/// let data = "The cake is a lie";
/// let meta = Metadata::generate_for_key(data.len());
/// let proto_meta = meta.to_proto();
/// assert_eq!(meta, Metadata::from_proto(&proto_meta)?);
///
/// # use tindercrypt::errors;
/// # Ok::<(), errors::Error>(())
/// ```
///
/// [`proto::metadata::Metadata`]: ../proto/metadata/struct.Metadata.html
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Metadata {
    /// The key derivation algorithm to be used.
    pub key_deriv_algo: KeyDerivationAlgorithm,
    /// The encryption algorithm to be used.
    pub enc_algo: EncryptionAlgorithm,
    /// The size of the ciphertext.
    ///
    /// Note that depending on the encryption algorithm used, the ciphertext
    /// may also contain its digest. So, this value also takes the digest into
    /// account.
    pub ciphertext_size: usize,
}

impl<'a> Metadata {
    /// Create the metadata from user-provided values.
    pub fn new(
        key_deriv_algo: KeyDerivationAlgorithm,
        enc_algo: EncryptionAlgorithm,
        plaintext_size: usize,
    ) -> Self {
        let ciphertext_size =
            Self::calculate_ciphertext_size(plaintext_size, &enc_algo);
        Self {
            key_deriv_algo,
            enc_algo,
            ciphertext_size,
        }
    }

    /// Calculate the ciphertext size, from the plaintext size and the
    /// encryption algorithm.
    pub fn calculate_ciphertext_size(
        plaintext_size: usize,
        enc_algo: &EncryptionAlgorithm,
    ) -> usize {
        match enc_algo {
            EncryptionAlgorithm::AES256GCM(_) => {
                plaintext_size + ring::aead::AES_256_GCM.tag_len()
            }
            EncryptionAlgorithm::ChaCha20Poly1305(_) => {
                plaintext_size + ring::aead::CHACHA20_POLY1305.tag_len()
            }
        }
    }

    /// Generate the necessary metadata for encrypting data with a symmetric
    /// key.
    ///
    /// The default suggestion for encrypting data with a symmetric key is to
    /// forego any key derivation algorithm, and just use the AES-256-GCM
    /// encryption algorithm.
    pub fn generate_for_key(plaintext_size: usize) -> Self {
        let key_deriv_algo = KeyDerivationAlgorithm::None;
        let enc_meta = EncryptionMetadata::generate();
        let enc_algo = EncryptionAlgorithm::AES256GCM(enc_meta);
        Self::new(key_deriv_algo, enc_algo, plaintext_size)
    }

    /// Generate the necessary metadata for encrypting data with a passphrase.
    ///
    /// The default suggestion for encrypting data with a passphrase is to use
    /// the PBKDF2 key derivation algorithm, and the AES-256-GCM encryption
    /// algorithm.
    pub fn generate_for_passphrase(plaintext_size: usize) -> Self {
        let key_deriv_meta = KeyDerivationMetadata::generate();
        let key_deriv_algo = KeyDerivationAlgorithm::PBKDF2(key_deriv_meta);
        let enc_meta = EncryptionMetadata::generate();
        let enc_algo = EncryptionAlgorithm::AES256GCM(enc_meta);
        Self::new(key_deriv_algo, enc_algo, plaintext_size)
    }

    /// Create the metadata from the respective protobuf-generated metadata.
    ///
    /// This method may return an error, if the protobuf-generated metadata
    /// have any invalid fields.
    pub fn from_proto(
        proto_meta: &pmeta::Metadata,
    ) -> Result<Self, errors::Error> {
        let err = Err(errors::Error::MetadataInvalid);

        // Parse the key derivation metadata.
        let proto_key_meta = proto_meta.get_key_deriv_meta();
        let key_deriv_algo =
            KeyDerivationAlgorithm::from_proto(proto_key_meta)?;

        // Parse the encryption metadata.
        let proto_enc_meta = proto_meta.get_enc_meta();
        let enc_algo = EncryptionAlgorithm::from_proto(proto_enc_meta)?;

        // Check that the ciphertext size is larger or equal to the minimum
        // ciphertext size for the given encryption algorithm.
        let ciphertext_size = proto_meta.ciphertext_size as usize;
        let min_ciphertext_size =
            Self::calculate_ciphertext_size(0, &enc_algo);
        if min_ciphertext_size > ciphertext_size {
            return err;
        }

        // Construct and return the metadata.
        Ok(Self {
            key_deriv_algo,
            enc_algo,
            ciphertext_size,
        })
    }

    /// Convert the metadata to the respective protobuf-generated metadata.
    pub fn to_proto(&self) -> pmeta::Metadata {
        let mut proto_meta = pmeta::Metadata::new();

        let key_meta = self.key_deriv_algo.to_proto();
        proto_meta.set_key_deriv_meta(key_meta);
        let enc_meta = self.enc_algo.to_proto();
        proto_meta.set_enc_meta(enc_meta);
        proto_meta.ciphertext_size = self.ciphertext_size as u64;

        proto_meta
    }

    /// Create a metadata struct from a serialized buffer.
    ///
    /// Deserialize the buffer that was created by the `.to_buf()` method into
    /// a tuple that contains the `Metadata` struct and its serialized size.
    /// If the buffer does not contain a metadata header or the header contains
    /// invalid fields, this method returns an error.
    pub fn from_buf(buf: &'a [u8]) -> Result<(Self, usize), errors::Error> {
        let mut is = protobuf::CodedInputStream::from_bytes(&buf);

        // Check that the buffer header contains a valid protobuf Metadata
        // message.
        let proto_meta = match is.read_message() {
            Ok(meta) => meta,
            Err(_) => return Err(errors::Error::MetadataMissing),
        };

        let proto_meta_size = is.pos() as usize;
        let meta = Metadata::from_proto(&proto_meta)?;
        Ok((meta, proto_meta_size))
    }

    /// Serialize a metadata struct into a buffer.
    ///
    /// Create a buffer that is large enough to hold the serialized metadata
    /// and the ciphertext. Then, serialize the metadata and store them at the
    /// start of the buffer. Finally, return the new buffer and the size of the
    /// serialized metadata.
    pub fn to_buf(&self) -> (Vec<u8>, usize) {
        let proto_meta = self.to_proto();

        // NOTE: It's probably safe to unwrap the result here, since the errors
        // it can return are by underlying functions that deal with smaller
        // buffers. In our case, we let the protobuf library create the buffer
        // itself, so any errors should be treated as bugs.
        let mut buf = proto_meta.write_length_delimited_to_bytes().unwrap();
        let proto_meta_size = buf.len();

        // FIXME: This operation may copy the contents of the buffer again. It
        // would be better if we knew the size of the serialized metadata
        // beforehand, so that we can create a buffer with the appropriate size
        // from the start. The protobuf Metadata message does have a
        // `.compute_size()` method, but we need the same for the varint.
        buf.resize(proto_meta_size + self.ciphertext_size, 0u8);
        (buf, proto_meta_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_function() {
        let err = Err(errors::Error::MetadataInvalid);
        let hash_fn = HashFunction::SHA256;
        let proto_hash_fn = pmeta::HashFunction::HASH_FUNCTION_SHA256;
        let inv_proto_hash_fn = pmeta::HashFunction::HASH_FUNCTION_INVALID;

        assert_eq!(HashFunction::from_proto(inv_proto_hash_fn), err);
        assert_eq!(HashFunction::from_proto(proto_hash_fn), Ok(hash_fn));
        assert_eq!(hash_fn.to_proto(), proto_hash_fn);
    }

    #[test]
    fn test_key_derivation_algorithm() {
        let err = Err(errors::Error::MetadataInvalid);
        let proto_none_algo =
            pmeta::KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_NONE;
        let proto_pbkdf2_algo =
            pmeta::KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_PBKDF2;

        // Check that conversion from invalid metadata returns an error.
        let inv_proto_meta = pmeta::KeyDerivationMetadata::new();
        assert_eq!(KeyDerivationAlgorithm::from_proto(&inv_proto_meta), err);

        // Check that converting to/from the "None" key derivation algorithm
        // works properly.
        let proto_meta = KeyDerivationAlgorithm::None.to_proto();
        assert_eq!(proto_meta.algo, proto_none_algo);
        assert_eq!(
            KeyDerivationAlgorithm::from_proto(&proto_meta),
            Ok(KeyDerivationAlgorithm::None)
        );

        // Check that converting to/from the "PBKDF2" key derivation algorithm
        // works properly.
        let meta = KeyDerivationMetadata::generate();
        let algo = KeyDerivationAlgorithm::PBKDF2(meta);
        let proto_meta = algo.to_proto();
        assert_eq!(proto_meta.algo, proto_pbkdf2_algo);
        assert_eq!(KeyDerivationAlgorithm::from_proto(&proto_meta), Ok(algo));

        // Check that invalid values are detected.
        //
        // * Wrong number of iterations.
        let mut proto_meta = algo.to_proto();
        proto_meta.iterations = 0;
        assert_eq!(KeyDerivationAlgorithm::from_proto(&proto_meta), err);
        // * Invalid hash function.
        let mut proto_meta = algo.to_proto();
        proto_meta.hash_fn = pmeta::HashFunction::HASH_FUNCTION_INVALID;
        assert_eq!(KeyDerivationAlgorithm::from_proto(&proto_meta), err);
        // * Wrong salt size.
        let mut proto_meta = algo.to_proto();
        proto_meta.salt = vec![];
        assert_eq!(KeyDerivationAlgorithm::from_proto(&proto_meta), err);
    }

    #[test]
    fn test_encryption_algorithm() {
        let err = Err(errors::Error::MetadataInvalid);
        let proto_aes_algo =
            pmeta::EncryptionAlgorithm::ENCRYPTION_ALGORITHM_AES256GCM;
        let proto_chacha_algo =
            pmeta::EncryptionAlgorithm::ENCRYPTION_ALGORITHM_CHACHA20_POLY1305;

        // Check that conversion from invalid metadata returns an error.
        let inv_proto_meta = pmeta::EncryptionMetadata::new();
        assert_eq!(EncryptionAlgorithm::from_proto(&inv_proto_meta), err);

        // Check that converting to/from the "AES-256-GCM"/"ChaCha20-Poly1305"
        // encrytion algorithms works properly.
        let meta = EncryptionMetadata::generate();
        let aes_algo = EncryptionAlgorithm::AES256GCM(meta);
        let meta = EncryptionMetadata::generate();
        let chacha_algo = EncryptionAlgorithm::ChaCha20Poly1305(meta);
        for (algo, proto_algo) in
            &[(aes_algo, proto_aes_algo), (chacha_algo, proto_chacha_algo)]
        {
            let mut proto_meta = algo.to_proto();
            assert_eq!(proto_meta.algo, *proto_algo);
            assert_eq!(
                EncryptionAlgorithm::from_proto(&proto_meta),
                Ok(algo.clone())
            );

            // Check that wrong nonce values are detected.
            proto_meta.nonce = vec![];
            assert_eq!(EncryptionAlgorithm::from_proto(&proto_meta), err);
        }
    }

    #[test]
    fn test_metadata_proto() {
        let err = Err(errors::Error::MetadataInvalid);

        // Check that conversion from invalid metadata returns an error.
        let inv_proto_meta = pmeta::Metadata::new();
        assert_eq!(Metadata::from_proto(&inv_proto_meta), err);

        // Check that converting to/from protobuf-generated metadata works
        // properly.
        let meta1 = Metadata::generate_for_passphrase(0);
        let enc_meta = EncryptionMetadata::generate();
        let enc_algo = EncryptionAlgorithm::ChaCha20Poly1305(enc_meta);
        let meta2 = Metadata::new(KeyDerivationAlgorithm::None, enc_algo, 0);

        for meta in &[meta1, meta2] {
            // Check that the ciphertext size is not 0, even though the
            // plaintext size is.
            assert!(meta.ciphertext_size > 0);

            // Check that the metadata remain the same after a double
            // conversion.
            let proto_meta = meta.to_proto();
            assert_eq!(Metadata::from_proto(&proto_meta), Ok(meta.clone()));

            // Check that invalid key derivation algorithms are detected.
            let mut proto_meta = meta.to_proto();
            proto_meta.clear_key_deriv_meta();
            assert_eq!(Metadata::from_proto(&proto_meta), err);

            // Check that invalid encryption algorithms are detected.
            let mut proto_meta = meta.to_proto();
            proto_meta.clear_enc_meta();
            assert_eq!(Metadata::from_proto(&proto_meta), err);

            // Check that invalid ciphertext sizes are detected.
            let mut proto_meta = meta.to_proto();
            proto_meta.ciphertext_size = 0;
            assert_eq!(Metadata::from_proto(&proto_meta), err);
        }
    }

    #[test]
    fn test_metadata_buf() {
        let missing_err = Err(errors::Error::MetadataMissing);
        let invalid_err = Err(errors::Error::MetadataInvalid);

        // Check that metadata serialization/deserialization works properly.
        let meta = Metadata::generate_for_passphrase(9);
        let (buf, meta_size) = meta.to_buf();
        assert_eq!(Metadata::from_buf(&buf), Ok((meta, meta_size)));

        // Check that buffers with missing/invalid metadata headers are
        // detected.
        assert_eq!(Metadata::from_buf(&[]), missing_err);

        let mut proto_meta = Metadata::generate_for_key(9).to_proto();
        proto_meta.clear_key_deriv_meta();
        let buf = proto_meta.write_length_delimited_to_bytes().unwrap();
        assert_eq!(Metadata::from_buf(&buf), invalid_err);
    }
}

//! # AEAD helpers
//!
//! This module contains some wrappers over the AEAD functions in the `ring`
//! library. You are advised to not use these low-level functions directly, and
//! instead use the functions provided by the [`cryptors`] module
//!
//! ## Examples
//!
//! You can encrypt (seal) and decrypt (open) a secret value as follows:
//!
//! ```
//! use ring::aead;
//! use tindercrypt::rand::fill_buf;
//! use tindercrypt::aead::{seal_in_place, open_in_place, NONCE_SIZE};
//!
//! let algo = &aead::AES_256_GCM;
//! let mut nonce = [0u8; NONCE_SIZE];
//! let aad = "My encryption context".as_bytes();
//! let mut key = vec![0u8; algo.key_len()];
//! let data = "The cake is a lie".as_bytes();
//!
//! // Create a unique nonce and key.
//! fill_buf(&mut nonce);
//! fill_buf(&mut key);
//!
//! // Create a buffer large enough to hold the ciphertext and its tag.
//! let mut buf = vec![0; data.len() + algo.tag_len()];
//! buf[..data.len()].copy_from_slice(&data);
//!
//! // Encrypt (seal) the data buffer in place, thereby ovewriting the
//! // plaintext data with the ciphertext, and appending a tag at the end.
//! seal_in_place(algo, nonce.clone(), &aad, &key, &mut buf);
//!
//! // Decrypt (open) the data buffer in place, thereby ovewriting ciphertext
//! // with the plaintext (the previous tag will not be removed).
//! open_in_place(algo, nonce.clone(), &aad, &key, &mut buf);
//! assert_eq!(data, &buf[..data.len()]);
//!
//! // Ensure that the nonce is never used again.
//! drop(nonce);
//!
//! ```
//!
//! [`cryptors`]: ../cryptors/index.html

use crate::errors;
use ring::aead;

/// The size of the nonces that `ring` expects.
pub const NONCE_SIZE: usize = 12;

/// Check if the provided key has the expected size for the specified
/// algorithm.
fn _check_key(
    algo: &'static aead::Algorithm,
    key: &[u8],
) -> Result<(), errors::Error> {
    if key.len() != algo.key_len() {
        return Err(errors::Error::KeySizeMismatch);
    }
    Ok(())
}

/// Check if the buffer where the output will be stored is large enough to
/// contain the tag.
fn _check_in_out(
    algo: &'static aead::Algorithm,
    in_out: &[u8],
) -> Result<(), errors::Error> {
    if in_out.len() < algo.tag_len() {
        return Err(errors::Error::BufferTooSmall);
    }
    Ok(())
}

/// Seal the contents of a data buffer in place.
///
/// This function is a wrapper around the `seal_in_place()` function of the
/// `ring` library. Its purpose is to simplify what needs to be passed to the
/// underlying function and perform some early checks. The produced ciphertext
/// will be stored in the same buffer as the plaintext, effectively erasing it.
///
/// This function accepts the following parameters:
///
/// * A `ring` AEAD algorithm, e.g., AES-256-GCM,
/// * A nonce buffer with a specific size. This nonce must **NEVER** be reused
///   for the same key.
/// * A reference to some data (additional authenticated data), which won't be
///   stored with the ciphertext, but will be used for the encryption and will
///   be required for the decryption as well.
/// * A reference to a symmetric key, whose size must match the size required
///   by the AEAD algorithm.
/// * A data buffer that holds the plaintext. The ciphertext will be
///   stored in this buffer, so it must be large enough to contain the
///   encrypted data and the tag as well. In practice, the user must craft a
///   buffer that starts with the plaintext and add an empty space at the end,
///   as large as the tag size expected by the algorithm.
///
/// This function returns an error if the key/buffer sizes are not the expected
/// ones. If the encryption fails, which should never happen in practice, this
/// function panics. If the encryption succeeds, it returns the length of the
/// plaintext.
pub fn seal_in_place(
    algo: &'static aead::Algorithm,
    nonce: [u8; NONCE_SIZE],
    aad: &[u8],
    key: &[u8],
    in_out: &mut [u8],
) -> Result<usize, errors::Error> {
    _check_key(algo, key)?;
    _check_in_out(algo, in_out)?;

    let tag_size = algo.tag_len();
    let key = aead::SealingKey::new(algo, key).unwrap();
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let aad = aead::Aad::from(aad);
    let res = aead::seal_in_place(&key, nonce, aad, in_out, tag_size);

    match res {
        Ok(size) => Ok(size - tag_size),
        Err(error) => panic!("Error during sealing: {:?}", error),
    }
}

/// Open the contents of a sealed data buffer in place.
///
/// This function is a wrapper around the `open_in_place()` function of the
/// `ring` library. Its purpose is to simplify what needs to be passed to the
/// underlying function and perform some early checks. The produced plaintext
/// will be stored in the same buffer as the ciphertext, effectively erasing it.
///
/// This function accepts the following parameters:
///
/// * A `ring` AEAD algorithm, e.g., AES-256-GCM,
/// * A nonce buffer with a specific size.
/// * A reference to some data (additional authenticated data), which must be
///   the same as the ones provided during the sealing process.
/// * A reference to a symmetric key, whose size must match the size required
///   by the AEAD algorithm.
/// * A data buffer that holds the ciphertext and its tag.
///
/// This function returns an error if the key/buffer sizes are not the expected
/// ones, or if the decryption process fails, e.g., due to a wrong key, nonce,
/// etc. If the decryption succeeds, it returns the length of the plaintext.
pub fn open_in_place(
    algo: &'static aead::Algorithm,
    nonce: [u8; NONCE_SIZE],
    aad: &[u8],
    key: &[u8],
    in_out: &mut [u8],
) -> Result<usize, errors::Error> {
    _check_key(algo, key)?;
    _check_in_out(algo, in_out)?;

    let key = aead::OpeningKey::new(algo, key).unwrap();
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let aad = aead::Aad::from(aad);
    let res = aead::open_in_place(&key, nonce, aad, 0, in_out);

    match res {
        Ok(plaintext) => Ok(plaintext.len()),
        Err(_) => Err(errors::Error::DecryptionError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUF_SIZE: usize = 36; // 36 bytes can contain the tag and data.

    #[test]
    fn test_key() {
        // Check that a key with incorrect size produces an error.
        // FIXME: Why can't I iterate over array pointers with different size?
        for algo in &[&aead::AES_256_GCM, &aead::CHACHA20_POLY1305] {
            for key in &[
                vec![],
                vec![0; 1],
                vec![0; algo.key_len() - 1],
                vec![0; algo.key_len() + 1],
            ] {
                assert_eq!(
                    _check_key(algo, key),
                    Err(errors::Error::KeySizeMismatch)
                );
            }
        }
    }

    #[test]
    fn test_in_out() {
        // Check that a key with incorrect size produces an error.
        // FIXME: Why can't I iterate over array pointers with different size?
        for algo in &[&aead::AES_256_GCM, &aead::CHACHA20_POLY1305] {
            for in_out in &[vec![], vec![0; 1], vec![0; algo.tag_len() - 1]] {
                assert_eq!(
                    _check_in_out(algo, in_out),
                    Err(errors::Error::BufferTooSmall)
                );
            }
        }
    }

    fn _test_seal_open(algo: &'static aead::Algorithm) {
        let nonce = [1; 12];
        let aad = [2; 9];
        let key = vec![3; algo.key_len()];
        let mut in_out: [u8; BUF_SIZE];
        let mut res: Result<usize, errors::Error>;
        let plaintext_size = BUF_SIZE - algo.tag_len();
        let exp_res = Ok(plaintext_size);
        let dec_err = Err(errors::Error::DecryptionError);
        let buf_err = Err(errors::Error::BufferTooSmall);
        let key_err = Err(errors::Error::KeySizeMismatch);

        // NOTE: We create a closure to avoid repetitions.
        let seal = || {
            let r;
            let mut _in_out = [4; BUF_SIZE];
            r = seal_in_place(algo, nonce.clone(), &aad, &key, &mut _in_out);
            assert_eq!(r, exp_res);
            _in_out
        };

        // Check that any type of data corruption makes decryption fail.
        //
        // Corrupted nonce.
        in_out = seal();
        let mut bad_nonce = nonce.clone();
        bad_nonce[0] = 9;
        res = open_in_place(algo, bad_nonce.clone(), &aad, &key, &mut in_out);
        assert_eq!(res, dec_err);

        // Corrupted additional authenticated data.
        in_out = seal();
        let mut bad_aad = aad.clone();
        bad_aad[0] = 9;
        res = open_in_place(algo, nonce.clone(), &bad_aad, &key, &mut in_out);
        assert_eq!(res, dec_err);

        // Corrupted key.
        in_out = seal();
        let mut bad_key = key.clone();
        bad_key[0] = 9;
        res = open_in_place(algo, nonce.clone(), &aad, &bad_key, &mut in_out);
        assert_eq!(res, dec_err);

        // Corrupted data.
        in_out = seal();
        let mut bad_in_out = in_out.clone();
        bad_in_out[0] = 9;
        res = open_in_place(algo, nonce.clone(), &aad, &key, &mut bad_in_out);
        assert_eq!(res, dec_err);

        // Corrupted tag.
        in_out = seal();
        let mut bad_in_out = in_out.clone();
        bad_in_out[in_out.len() - 1] = 9;
        res = open_in_place(algo, nonce.clone(), &aad, &key, &mut bad_in_out);
        assert_eq!(res, dec_err);

        // Incomplete data buffer.
        res = seal_in_place(algo, nonce.clone(), &aad, &key, &mut []);
        assert_eq!(res, buf_err);
        res = open_in_place(algo, nonce.clone(), &aad, &key, &mut []);
        assert_eq!(res, buf_err);

        // Incomplete key.
        res = seal_in_place(algo, nonce.clone(), &aad, &[], &mut in_out);
        assert_eq!(res, key_err);
        res = open_in_place(algo, nonce.clone(), &aad, &[], &mut in_out);
        assert_eq!(res, key_err);

        // Incorrect encryption algorithm.
        let algo2: &'static aead::Algorithm;
        if algo == &aead::AES_256_GCM {
            algo2 = &aead::CHACHA20_POLY1305;
        } else {
            algo2 = &aead::AES_256_GCM;
        }

        in_out = seal();
        res = open_in_place(algo2, nonce.clone(), &aad, &key, &mut in_out);
        assert_eq!(res, dec_err);

        // Correct decryption.
        in_out = seal();
        res = open_in_place(algo, nonce.clone(), &aad, &key, &mut in_out);
        assert_eq!(res, exp_res);
        assert_eq!(in_out[..res.unwrap()], vec![4u8; res.unwrap()][..]);
    }

    #[test]
    fn test_seal_open_aes() {
        _test_seal_open(&aead::AES_256_GCM);
    }

    #[test]
    fn test_seal_open_chacha20() {
        _test_seal_open(&aead::CHACHA20_POLY1305);
    }
}

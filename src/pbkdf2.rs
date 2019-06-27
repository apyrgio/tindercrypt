//! # PBKDF2 helpers
//!
//! This module contains helpers for the PBKDF2 algorithm.

use crate::errors;
use core::num;
use ring::{digest, pbkdf2};

/// Cryptographically create a symmetric key from a secret value.
///
/// Create a symmetric key from a secret value, based on various PBKDF2
/// parameters; an HMAC function, a salt and a number of iterations.
///
/// This method returns an error if the parameters are too weak, e.g., a SHA-1
/// digest function, zero number of iterations or no salt. Also, it returns an
/// error if the user has not provided a buffer for the key or a secret value.
///
/// ## Examples
///
/// A safe method to derive a key with PBKDF2 is the following:
///
/// ```
/// use tindercrypt::pbkdf2::derive_key;
/// use tindercrypt::rand::fill_buf;
/// use ring::digest;
///
/// let digest_algo = &digest::SHA256;
/// let iterations = 100000;
/// let mut salt = [0u8; 32];
/// let secret = "My secret password".as_bytes();
/// let mut key = [0u8; 32];
///
/// fill_buf(&mut salt);
/// derive_key(digest_algo, iterations, &salt, &secret, &mut key);
/// ```
pub fn derive_key(
    digest_algo: &'static digest::Algorithm,
    iterations: usize,
    salt: &[u8],
    secret: &[u8],
    key: &mut [u8],
) -> Result<(), errors::Error> {
    if digest_algo == &digest::SHA1 || iterations < 1 || salt.len() == 0 {
        return Err(errors::Error::CryptoParamsWeak);
    }

    if secret.len() == 0 || key.len() == 0 {
        return Err(errors::Error::PassphraseTooSmall);
    }

    let iterations = num::NonZeroU32::new(iterations as u32).unwrap();
    pbkdf2::derive(digest_algo, iterations, salt, secret, key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkd2_derive_key() {
        let mut salt = [9; 10];
        let mut secret = [99; 10];
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        let mut key3 = [0u8; 32];
        let mut key4 = [0u8; 32];
        let mut res: Result<(), errors::Error>;
        let params_err = Err(errors::Error::CryptoParamsWeak);
        let size_err = Err(errors::Error::PassphraseTooSmall);

        // Check that weak parameters and empty buffers are reported as errors.
        res = derive_key(&digest::SHA1, 1, &salt, &secret, &mut key1);
        assert_eq!(res, params_err);
        res = derive_key(&digest::SHA256, 0, &salt, &secret, &mut key1);
        assert_eq!(res, params_err);
        res = derive_key(&digest::SHA256, 1, &[], &secret, &mut key1);
        assert_eq!(res, params_err);
        res = derive_key(&digest::SHA256, 1, &salt, &[], &mut key1);
        assert_eq!(res, size_err);
        res = derive_key(&digest::SHA256, 1, &salt, &secret, &mut []);
        assert_eq!(res, size_err);

        // Check that key derivation works, and that changes in the salt and
        // secret produce different keys.
        res = derive_key(&digest::SHA256, 1, &salt, &secret, &mut key1);
        assert!(res.is_ok());
        salt[0] = 0;
        res = derive_key(&digest::SHA256, 1, &salt, &secret, &mut key2);
        assert!(res.is_ok());
        salt[0] = 9;
        secret[0] = 0;
        res = derive_key(&digest::SHA256, 1, &salt, &secret, &mut key3);
        assert!(res.is_ok());
        secret[0] = 99;
        res = derive_key(&digest::SHA256, 1, &salt, &secret, &mut key4);
        assert!(res.is_ok());

        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
        assert_eq!(key1, key4);
    }
}

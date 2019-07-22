//! # Tindercrypt errors

use std::fmt;

/// The errors that can be returned by the library.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// The provided data buffer is too small for the requested action.
    BufferTooSmall,
    /// The provided passphrase is too small for the key derivation process.
    PassphraseTooSmall,
    /// The provided key size was not the expected one.
    KeySizeMismatch,
    /// The provided parameters to a crypto function are weak.
    CryptoParamsWeak,
    /// Could not decrypt the data, e.g., due to a bad key, wrong nonce,
    /// corrupted tag.
    DecryptionError,
    /// The provided buffer does not start with the expected metadata header.
    MetadataMissing,
    /// The metadata header of the encrypted buffer contains invalid values.
    MetadataInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BufferTooSmall => {
                write!(f, "The provided buffer is shorter than expected")
            }
            Error::PassphraseTooSmall => {
                write!(f, "The provided passphrase is shorter than expected")
            }
            Error::KeySizeMismatch => write!(
                f,
                "The provided key does not have the required length for the \
                 encryption algorithm"
            ),
            Error::CryptoParamsWeak => write!(
                f,
                "The provided parameters for the encryption are too weak"
            ),
            Error::DecryptionError => {
                write!(f, "Could not decrypt the ciphertext")
            }
            Error::MetadataMissing => write!(
                f,
                "The provided buffer does not include a metadata header"
            ),
            Error::MetadataInvalid => {
                write!(f, "The provided buffer has an invalid metadata header")
            }
        }
    }
}

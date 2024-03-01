//! # Tindercrypt errors

/// The errors that can be returned by the library.
#[derive(thiserror::Error, Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// The provided data buffer is too small for the requested action.
    #[error("The provided buffer is shorter than expected")]
    BufferTooSmall,
    /// The provided passphrase is too small for the key derivation process.
    #[error("The provided passphrase is shorter than expected")]
    PassphraseTooSmall,
    /// The provided key size was not the expected one.
    #[error(
        "The provided key does not have the required length for the \
         encryption algorithm"
    )]
    KeySizeMismatch,
    /// The provided parameters to a crypto function are weak.
    #[error("The provided parameters for the encryption are too weak")]
    CryptoParamsWeak,
    /// Could not decrypt the data, e.g., due to a bad key, wrong nonce,
    /// corrupted tag.
    #[error("Could not decrypt the ciphertext")]
    DecryptionError,
    /// The provided buffer does not start with the expected metadata header.
    #[error("The provided buffer does not include a metadata header")]
    MetadataMissing,
    /// The metadata header of the encrypted buffer contains invalid values.
    #[error("The provided buffer has an invalid metadata header")]
    MetadataInvalid,
}

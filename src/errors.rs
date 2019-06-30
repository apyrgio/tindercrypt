//! # Tindercrypt errors

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

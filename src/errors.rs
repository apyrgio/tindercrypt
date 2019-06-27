//! # Tindercrypt errors

/// The errors that can be returned by the library.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// The provided buffer does not start with the expected metadata header.
    MetadataMissing,
    /// The metadata header of the encrypted buffer contains invalid values.
    MetadataInvalid,
}

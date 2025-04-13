//! # Tindercrypt
//!
//! Tindercrypt is a library that supports data encryption with symmetric
//! cryptographic keys or passwords/passphrases. It supports [AES256-GCM] and
//! [ChaCha20-Poly1305] for encryption/decryption, and [PBKDF2] for key
//! derivation. These cryptographic primitives are provided by the [Ring]
//! crypto library.
//!
//! Tindercrypt's main goal is to provide a safe and easy API for data
//! encryption. The user of this library simply chooses an encryption algorithm
//! and provides a key/passphrase to encrypt their data. To decrypt their data,
//! they provide the same key/passphrase. Behind the scenes, Tindercrypt
//! generates the necessary encryption metadata (salts, nonces, etc.) and
//! bundles them with the encrypted data, so that it can retrieve them when
//! decrypting the data later on.
//!
//! You can learn how Tindercrypt handles encryption metadata in the
//! [`metadata`] module.
//!
//! [AES256-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
//! [ChaCha20-Poly1305]: https://tools.ietf.org/html/rfc7539
//! [PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
//! [Ring]: https://github.com/briansmith/ring
//! [`metadata`]: metadata/index.html

#![deny(
    warnings,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    unused_extern_crates,
    unused_must_use,
    unused_results,
    variant_size_differences
)]

pub mod aead;
pub mod cryptors;
pub mod errors;
pub mod metadata;
pub mod pbkdf2;
#[path = "../proto/mod.rs"]
pub mod proto;
pub mod rand;

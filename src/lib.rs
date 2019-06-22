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
//! [AES256-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
//! [ChaCha20-Poly1305]: https://tools.ietf.org/html/rfc7539
//! [PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
//! [Ring]: https://github.com/briansmith/ring

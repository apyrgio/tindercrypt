# Tindercrypt

A library that supports data encryption with symmetric cryptographic keys or
passwords/passphrases. Uses [Protocol Buffers] for the serialization of the
encryption metadata (salts, nonces, etc.) and is based on the [ring] Rust crate
for the cryptographic primitives.

## Overview

Tindercrypt's main goal is to provide a safe and easy API for data
encryption. The user of this library simply chooses an encryption algorithm
and provides a key/passphrase to encrypt their data. To decrypt their data,
they provide the same key/passphrase. Behind the scenes, Tindercrypt
generates the necessary encryption metadata (salts, nonces, etc.) and
bundles them with the encrypted data, so that it can retrieve them when
decrypting the data later on.

Features:

* Does not reinvent crypto. Uses the cryptographic primitives of the
  well-tested [ring] crate; [PBKDF2] for key derivation,
  [AES256-GCM]/[ChaCha20-Poly1305] for symmetric encryption.
* Sane defaults for all cryptographic operations; random nonces and
  salts, high number of key derivation iterations.
* Extensibility and compatibility with older versions through [Protocol
  buffers].
* No book-keeping necessary by the user; all required metadata for
  the decryption are bundled with the ciphertext.
* Offers a simple, multi-platform CLI tool that encrypts files with a
  passphrase.

## Examples

You can encrypt (seal) a data buffer with a passphrase as follows:

```rust
use tindercrypt::cryptors::RingCryptor;

let plaintext = "The cake is a lie".as_bytes();
let pass = "My secret passphrase".as_bytes();
let cryptor = RingCryptor::new();

let ciphertext = cryptor.seal_with_passphrase(pass, plaintext)?;
let plaintext2 = cryptor.open(pass, &ciphertext)?;
assert_eq!(plaintext2, plaintext);
```

The equivalent operation in the CLI tool is the following:

```
$ echo The cake is a lie > plaintext
$  export TINDERCRYPT_PASSPHRASE="My secret passphrase"  # Note the extra space.
$ tindercrypt encrypt -i plaintext -o ciphertext
$ tindercrypt decrypt -i ciphertext
The cake is a lie
```

## Installation

* From cargo:

```
$ cargo install tindercrypt
```

* From source:

```
$ git clone https://github.com/apyrgio/tindercrypt
$ cd tindercrypt
$ cargo build --release
$ ./target/release/tindercrypt --help
Tindecrypt: File encryption tool ...
```

## Development

Clone this repo, make changes to the code and ensure that the tests pass:

```
$ cargo test
```

For changes in the `.proto` file, do the following:

* Check if the `.proto` file passes the lint checks of Uber's [`prototool`].
* Compile the `.proto` file with `cargo build --features proto-gen`.
* Commit the generated Rust code.

Finally, read the [`NOTICE.md`] file for the legal status of the project.

## Legal

Licensed under MPL-2.0. Please read the [`NOTICE.md`] and [`LICENSE`] files for
the full copyright and license information. If you feel like putting your
mental stability to a test, feel free to read the [`LEGAL.md`] file for a foray
into the waters of copyright law, and a glimpse of how they can be boring and
dangerous at the same time.

[ring]: https://github.com/briansmith/ring
<!--[protobuf]: https://github.com/stepancheg/rust-protobuf-->
[Protocol Buffers]: https://developers.google.com/protocol-buffers/
[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
[AES256-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[ChaCha20-Poly1305]: https://tools.ietf.org/html/rfc7539
[`prototool`]: https://github.com/uber/prototool
[`NOTICE.md`]: /NOTICE.md
[`LICENSE`]: /LICENSE
[`LEGAL.md`]: /LEGAL.md

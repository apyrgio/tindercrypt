# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic
Versioning].

## [Unreleased]

## [0.3.2] - 2021-06-21

### Fixed

- Fix a `rustdoc::bare_urls` warning for some links that we used in our
  footnotes and did not have any style indication, by formatting them as
  hyperliks.

## [0.3.1] - 2021-04-20

### Fixed

- Temporarily fix a build error for nightly Rust. In a nutshell, the generated
  Rust code for our proto files triggers a compiler warning in nightly Rust,
  which we ultimately treat as an error. Until this is fixed upstream, we
  silence this warning. See also:

  * https://github.com/stepancheg/rust-protobuf/issues/551
  * https://github.com/rust-lang/rust/issues/64266

- Remove the temporary workaround for the aforementioned Rust warning, since the
  newly generated Rust code semi-resolves it. See also:

  * https://github.com/stepancheg/rust-protobuf/issues/551#issuecomment-802221146

### Changed

- Bump the dialoguer dependency to v0.8.0, to fix a compilation error.

## [0.3.0] - 2021-01-11

### Added

- Allow users to derive a key from a secret value and the encryption metadata.

### Removed

- Remove the key derivation process that was performed internally in the
  following `RingCryptor` methods:

  * `seal_in_place`
  * `seal_with_meta`
  * `seal_with_key`
  * `open_in_place`
  * `open_with_meta`

  The change should impact just the users that used key derivation (PBKDF2) and
  passed a passphrase to any of the above functions. If you are affected, you
  can manually derive the key and pass it to the above functions. For more info,
  see the examples in the `RingCryptor` documentation.

  Note that the following methods are still performing key derivation
  internally:

  * `seal_with_passphrase`
  * `open`

  Finally, the reason for the removal was not security-related, but to give more
  control to the users on this front ([#6]).

## [0.2.2] - 2020-04-13

### Changed

- Use the `thiserror` crate to make the library errors implement the `Error`
  trait, and remove some boilerplate code.

## [0.2.1] - 2020-03-30

### Changed

- Move the CLI dependencies under a `cli` feature flag, so that users of the
  library don't need to pull them.

## [0.2.0] - 2020-03-22

### Added

- Add Windows support.
- Add a CI pipeline based on Github Actions. This pipeline tests the project
  on Ubuntu, MacOS and Windows platforms, and creates build artifacts for them.

### Changed

- Bump the dependencies to their newest versions.

### Fixed

- Fix some build warnings, that were ultimately treated as errors, by
  updating `protoc-rust` and generating new Rust code from our `.proto` files.
  These build warnings started to appear due to new versions of `rustc`.

### Removed

- Remove support for the `HMAC-SHA512/256` hash function, used in conjunction
  with PBKDF2 for key derivation. This hash function was removed by the `ring`
  library, so we're left with no choice but to remove it from Tindercrypt it as
  well.

## [0.1.1] - 2019-08-10

Version bump so that the Github tag and crates.io tag can be aligned.

## [0.1.0] - 2019-08-10

Initial release.

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[#6]: https://github.com/apyrgio/tindercrypt/issues/6

[Unreleased]: https://github.com/apyrgio/tindercrypt/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/apyrgio/tindercrypt/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/apyrgio/tindercrypt/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/apyrgio/tindercrypt/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/apyrgio/tindercrypt/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/apyrgio/tindercrypt/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/apyrgio/tindercrypt/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/apyrgio/tindercrypt/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/apyrgio/tindercrypt/releases/tag/v0.1.0

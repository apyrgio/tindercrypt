# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic
Versioning].

## [Unreleased]

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

[Unreleased]: https://github.com/apyrgio/tindercrypt/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/apyrgio/tindercrypt/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/apyrgio/tindercrypt/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/apyrgio/tindercrypt/releases/tag/v0.1.0

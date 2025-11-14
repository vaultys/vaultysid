# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-XX

### Added
- Initial release of VaultysId Rust implementation
- Ed25519 digital signature support
- X25519 key exchange (Diffie-Hellman)
- Identity management for Machine, Person, and Organization types
- DHIES (Diffie-Hellman Integrated Encryption Scheme) for authenticated encryption
- DID (Decentralized Identifier) document generation
- Challenge-response authentication protocol
- Backwards compatibility with deprecated key manager format
- MessagePack serialization support
- Secure memory handling with automatic zeroization
- Comprehensive test suite with cross-language compatibility tests
- IdManager for high-level identity and contact management
- File encryption and signature verification
- Web of trust functionality
- HMAC generation for API authentication
- Memory channel for secure communication between identities

### Security
- Constant-time comparison for MAC verification
- Automatic clearing of sensitive data using `zeroize` crate
- Secure random number generation
- Protection against replay attacks in DHIES

### Fixed
- XNonce creation to avoid deprecation warnings with generic-array
- Challenge signature verification using BTreeMap for consistent serialization
- Proper field name mapping in IdData deserialization

[Unreleased]: https://github.com/vaultys/vaultysid/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vaultys/vaultysid/releases/tag/v0.1.0
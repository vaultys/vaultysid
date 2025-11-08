# VaultysId Rust Implementation

A Rust implementation of the VaultysId cryptographic identity library, providing Ed25519 signing, X25519 key exchange, and identity management functionality.

## Features

- **Ed25519 Signing**: Digital signatures using Ed25519
- **X25519 Key Exchange**: Diffie-Hellman key exchange using X25519
- **Identity Management**: Support for Machine, Person, and Organization identity types
- **DHIES Encryption**: Diffie-Hellman Integrated Encryption Scheme for authenticated encryption
- **Backwards Compatibility**: Support for deprecated key manager format
- **DID Support**: Decentralized Identifier (DID) document generation
- **Secure Memory**: Automatic zeroing of sensitive data using `zeroize`

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
vaultysid = { path = "path/to/vaultysid/rust" }
```

## Usage

### Basic Identity Generation

```rust
use vaultysid::VaultysId;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate different types of identities
    let machine_id = VaultysId::generate_machine().await?;
    let person_id = VaultysId::generate_person().await?;
    let org_id = VaultysId::generate_organization().await?;
    
    // Get the DID (Decentralized Identifier)
    println!("Machine DID: {}", machine_id.did());
    println!("Person DID: {}", person_id.did());
    
    Ok(())
}
```

### Signing and Verification

```rust
use vaultysid::VaultysId;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id = VaultysId::generate_person().await?;
    
    // Sign a challenge
    let challenge = b"Hello, World!";
    let signed = id.sign_challenge(challenge).await?;
    
    // Verify the signature
    let is_valid = id.verify_challenge(challenge, &signed.signature)?;
    assert!(is_valid);
    
    Ok(())
}
```

### Key Exchange (Diffie-Hellman)

```rust
use vaultysid::Ed25519Manager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = Ed25519Manager::generate()?;
    let bob = Ed25519Manager::generate()?;
    
    let alice_cypher = alice.get_cypher_ops()?;
    let bob_cypher = bob.get_cypher_ops()?;
    
    // Both derive the same shared secret
    let shared_alice = alice_cypher.diffie_hellman(&bob.cypher.public_key)?;
    let shared_bob = bob_cypher.diffie_hellman(&alice.cypher.public_key)?;
    
    assert_eq!(shared_alice, shared_bob);
    
    Ok(())
}
```

### Import and Export

```rust
use vaultysid::{VaultysId, Ed25519Manager};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Export identity as bytes
    let original = VaultysId::generate_machine().await?;
    let id_bytes = original.id();
    
    // Import from bytes (public keys only)
    let imported = VaultysId::from_id(&id_bytes, None, None)?;
    assert_eq!(original.did(), imported.did());
    
    // Export and import with secret keys
    let manager = Ed25519Manager::generate()?;
    let secret = manager.get_secret()?;
    let restored = Ed25519Manager::from_secret(&secret)?;
    
    Ok(())
}
```

### HMAC Generation

```rust
use vaultysid::Ed25519Manager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = Ed25519Manager::generate()?;
    let cypher = manager.get_cypher_ops()?;
    
    // Generate HMAC for a message
    let hmac = cypher.hmac("api/endpoint/123")?;
    
    if let Some(hmac_value) = hmac {
        println!("HMAC: {}", hex::encode(&hmac_value));
    }
    
    Ok(())
}
```

## Module Structure

- **`vaultys_id`**: Main VaultysId struct and identity management
- **`key_manager`**: Key management implementations
  - `Ed25519Manager`: Modern Ed25519/X25519 key manager
  - `DeprecatedKeyManager`: Backwards-compatible key manager
  - `CypherManager`: Base implementation for cypher operations
  - `AbstractKeyManager`: Trait definitions for key managers
- **`crypto`**: Cryptographic utilities (hash, HMAC, random bytes, etc.)
- **`error`**: Error types and handling

## Key Types

### VaultysId Types
- `TYPE_MACHINE` (0): Machine identity
- `TYPE_PERSON` (1): Person identity  
- `TYPE_ORGANIZATION` (2): Organization identity
- `TYPE_FIDO2` (3): FIDO2 hardware key (not implemented)
- `TYPE_FIDO2PRF` (4): FIDO2 with PRF (not implemented)

### Capabilities
- `Private`: Full capability with secret keys
- `Public`: Public key only (verification only)

## Security Features

- **Memory Safety**: Uses Rust's ownership system for memory safety
- **Zeroization**: Automatic clearing of sensitive data from memory using `zeroize`
- **Constant-Time Operations**: Constant-time comparison for MAC verification
- **Strong Cryptography**: Ed25519 for signatures, X25519 for key exchange

## Running Examples

```bash
# Run the basic usage example
cargo run --example basic_usage

# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture
```

## Testing

The library includes comprehensive tests:

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration_tests

# All tests with coverage (requires cargo-tarpaulin)
cargo tarpaulin
```

## Differences from TypeScript Version

This Rust implementation maintains compatibility with the TypeScript version while providing:

1. **Memory Safety**: Automatic memory management and zeroization
2. **Performance**: Native performance for cryptographic operations
3. **Type Safety**: Compile-time type checking
4. **Simplified Dependencies**: No need for BIP32 derivation (simplified in DeprecatedKeyManager)
5. **Async/Sync Options**: Both async and sync APIs where appropriate

Note: Some features like Saltpack encryption/decryption are not fully implemented in this version. The DHIES encryption provides an alternative authenticated encryption scheme.

## License

[Same as the parent VaultysId project]

## Contributing

Contributions are welcome! Please ensure all tests pass and add tests for new functionality.

```bash
# Format code
cargo fmt

# Run clippy for lints
cargo clippy -- -D warnings

# Run tests
cargo test
```

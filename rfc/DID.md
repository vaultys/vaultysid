# Request for Comments: Vaultys Decentralized Identity Keyring Protocol

## 1. Introduction

This document specifies the Vaultys Decentralized Identity Keyring Protocol, a comprehensive system for managing cryptographic identities across different devices and contexts. The protocol enables secure key management, authentication, encryption, and identity portability while supporting both software-based and hardware-based key storage.

### 1.1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.2. Abbreviations

* DID: Decentralized Identifier
* PRF: Pseudo-Random Function
* HMAC: Hash-based Message Authentication Code
* DHIES: Diffie-Hellman Integrated Encryption Scheme
* COSE: CBOR Object Signing and Encryption
* FIDO2: Fast Identity Online 2.0 (WebAuthn)

## 2. Protocol Overview

The Vaultys Decentralized Identity Keyring Protocol provides a comprehensive framework for managing cryptographic identities with the following features:

1. Multiple identity types (machine, person, organization, FIDO2-based)
2. Support for both software and hardware-based key storage
3. Standardized key derivation and management
4. Secure messaging through authenticated encryption
5. Identity verification through challenge-response mechanisms
6. Key rotation and revocation mechanisms
7. Interoperability with W3C DID standards

## 3. Identity Types

### 3.1. Enumerated Identity Types

The protocol defines the following identity types, encoded as the first byte of the identity:

| Value | Type         | Description                                   |
|-------|--------------|-----------------------------------------------|
| 0     | MACHINE      | Identity for autonomous systems or devices    |
| 1     | PERSON       | Identity for individual human users           |
| 2     | ORGANIZATION | Identity for organizations or groups          |
| 3     | FIDO2        | Identity bound to a FIDO2 authenticator       |
| 4     | FIDO2PRF     | Identity using FIDO2 PRF extension            |

### 3.2. Identity Structure

Each identity consists of:

1. A type indicator (1 byte)
2. Identity-specific cryptographic material:
   - For software-based identities: a key manager with signing and encryption keys
   - For hardware-based identities: FIDO2 credential information and encryption keys

## 4. Key Manager Specification

### 4.1. KeyManager Overview

The KeyManager is the core component responsible for cryptographic operations and key management for software-based identities. It maintains:

1. A proof key for identity verification
2. A signing key pair for authentication and signatures
3. An encryption key pair for secure messaging
4. Optional entropy for key derivation

### 4.2. Key Derivation

Software-based identities derive keys from entropy using a deterministic path:

1. Generate a 512-bit seed using SHA-512(entropy)
2. Derive the proof key using BIP32 path `m/1'/0'/{swapIndex}'`
3. Derive the signing key using BIP32 path `m/1'/0'/{swapIndex}'/0'`
4. Derive the encryption key using SHA-256 of the second half of the seed

### 4.3. Identity Serialization

The identity is serialized using MessagePack encoding with the following structure:

```
{
  "v": version,            // Version (0 or 1)
  "p": proof,              // Proof key hash
  "x": signingKey,         // Public signing key
  "e": encryptionKey       // Public encryption key
}
```

This serialized structure is prefixed with the identity type byte to form the complete identity.

## 5. FIDO2-Based Identities

### 5.1. FIDO2 Identity Creation

FIDO2-based identities are created by:

1. Generating a new WebAuthn credential
2. Extracting the COSE public key
3. Generating or deriving an encryption key
4. For FIDO2PRF: Using the PRF extension to derive keys

### 5.2. FIDO2 Identity Structure

FIDO2 identities serialize the following information:

```
{
  "v": version,            // Version (0 or 1)
  "c": coseKey,            // COSE-encoded public key
  "e": encryptionKey       // Public encryption key
}
```

For private key operations, additional fields are included:

```
{
  "f": fidId,              // WebAuthn credential ID
  "t": transports          // Bitmask of supported transports
}
```

### 5.3. FIDO2 PRF Extension

For FIDO2PRF identities, the WebAuthn PRF extension is used to derive key material. The salt `"VaultysID salt"` is used to ensure consistent key derivation across operations.

## 6. Cryptographic Operations

### 6.1. Authentication and Signatures

The protocol supports two signature mechanisms:

1. Software-based signatures using Ed25519
2. Hardware-based signatures using FIDO2 authenticators

For FIDO2 signatures, the protocol uses a specialized format to include authenticator data:

```
{
  "s": signature,          // Actual signature bytes
  "c": clientDataJSON,     // WebAuthn client data
  "a": authenticatorData   // WebAuthn authenticator data
}
```

### 6.2. Encryption

The protocol supports multiple encryption methods:

1. **DHIES** (Diffie-Hellman Integrated Encryption Scheme): For direct secure messaging between two identities
2. **Saltpack**: For multi-recipient encryption and anonymous encryption

#### 6.2.1. DHIES Format

DHIES encrypted messages have the following structure:

```
+----------------+----------------+----------------+----------------+
| Nonce          | Ephemeral Key  | Ciphertext     | MAC            |
| (24 bytes)     | (32 bytes)     | (variable)     | (32 bytes)     |
+----------------+----------------+----------------+----------------+
```

### 6.3. Key Agreement (Diffie-Hellman)

The protocol uses X25519 for key agreement operations, enabling two parties to establish a shared secret for encrypted communications.

### 6.4. HMAC-based Pseudo-Random Functions (PRF)

The protocol uses HMAC-SHA256 for generating deterministic values based on the identity's encryption key:

```
HMAC-SHA256(encryptionKey, "VaultysID/{message}/end")
```

## 7. Decentralized Identifier (DID) Integration

### 7.1. DID Method

The protocol defines the `did:vaultys` method with the following format:

```
did:vaultys:<40-character-fingerprint>
```

The fingerprint is derived from:
1. The identity type byte
2. SHA-224 hash of the identity's key material

### 7.2. DID Document

Each identity can generate a W3C compliant DID document with the following structure:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:vaultys:<fingerprint>",
  "authentication": [{
    "id": "did:vaultys:<fingerprint>#keys-1",
    "type": "<authType>",
    "controller": "did:vaultys:<fingerprint>",
    "publicKeyMultibase": "<base64-public-key>"
  }],
  "keyAgreement": [{
    "id": "did:vaultys:<fingerprint>#keys-2",
    "type": "<encType>",
    "controller": "did:vaultys:<fingerprint>",
    "publicKeyMultibase": "<base64-public-key>"
  }]
}
```

## 8. Key Rotation and Revocation

### 8.1. Swapping Certificate

The protocol enables key rotation through a swapping certificate mechanism:

```
{
  "newId": Buffer,         // New identity ID
  "proofKey": Buffer,      // Original proof key
  "timestamp": number,     // Operation timestamp
  "signature": Buffer      // Signature by proof key
}
```

### 8.2. Verification Process

To verify a swapping certificate:

1. Verify the proof key matches the identity's proof hash
2. Verify the signature over the concatenation of newId, proofKey, and timestamp

## 9. Time-Based Operations

### 9.1. One-Time Password (OTP) Generation

The protocol supports time-based one-time passwords for authentication:

```
OTP = HMAC-SHA256(secretKey, "OTP-" + Math.floor(Date.now() / timelock))
```

Where `timelock` is a time period (defaulting to 1 hour).

## 10. Security Considerations

### 10.1. Key Storage and Management

1. Private keys MUST be securely erased from memory after use
2. Hardware-backed keys SHOULD be preferred for high-security scenarios
3. The protocol SHOULD use secure random number generation for all operations

### 10.2. Authentication

1. User verification SHOULD be requested for sensitive operations
2. FIDO2 authenticators SHOULD use user verification when available

### 10.3. Forward Secrecy

The protocol does not inherently provide forward secrecy for all operations. Applications requiring forward secrecy SHOULD implement additional key rotation mechanisms.

## 11. Implementation Considerations

### 11.1. Cross-Platform Support

1. Implementations MUST handle binary data correctly across different platforms
2. The protocol supports both browser and native environments

### 11.2. Hardware Support

The protocol is designed to work with:
1. FIDO2-compliant authenticators (e.g., YubiKeys, Windows Hello, Apple Touch ID)
2. WebAuthn API in modern browsers
3. PRF-supporting authenticators for FIDO2PRF identities

## 12. Interoperability

### 12.1. Versioning

The protocol supports two serialization versions (0 and 1):
- Version 0: Legacy serialization format
- Version 1: MessagePack-based serialization format

Implementations MUST support both versions for backward compatibility.

### 12.2. Messaging Formats

The protocol defines standard formats for:
1. Identity serialization
2. Signature representation
3. Encrypted message structure

## 13. Examples

### 13.1. Creating a Software-Based Identity

```typescript
// Generate a new person identity
const personId = await VaultysId.generatePerson();

// Get the identity's DID
const did = personId.did;  // "did:vaultys:0123456789abcdef0123456789abcdef01234567"

// Export the identity's secret for backup
const secret = personId.getSecret();
```

### 13.2. Creating a FIDO2-Based Identity

```typescript
// Create a new FIDO2 identity (e.g., using Windows Hello or YubiKey)
const fido2Id = await VaultysId.createWebauthn();

// The identity is bound to the hardware authenticator
const isHardware = fido2Id.isHardware();  // true
```

### 13.3. Encrypting a Message

```typescript
// Encrypt a message for a recipient
const encryptedMessage = await senderId.dhiesEncrypt(
  "Secret message",
  recipientId.id
);

// Decrypt the message
const decryptedMessage = await recipientId.dhiesDecrypt(
  encryptedMessage,
  senderId.id
);
```

### 13.4. Multi-Recipient Encryption

```typescript
// Encrypt a message for multiple recipients
const encryptedMessage = await VaultysId.encrypt(
  "Secret message for multiple recipients",
  [recipient1.id, recipient2.id, recipient3.id]
);

// Each recipient can decrypt the message
const decryptedMessage = await recipient1.decrypt(encryptedMessage);
```

## 14. References

### 14.1. Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

[WebAuthn] W3C, "Web Authentication: An API for accessing Public Key Credentials", https://www.w3.org/TR/webauthn/

[DID-CORE] W3C, "Decentralized Identifiers (DIDs) v1.0", https://www.w3.org/TR/did-core/

[BIP32-ED25519] "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace", https://github.com/stricahq/bip32ed25519

### 14.2. Informative References

[SALTPACK] "Saltpack: a modern crypto messaging format", https://saltpack.org/

[NACL] Bernstein, D.J., et al., "Networking and Cryptography library", https://nacl.cr.yp.to/

[DHIES] Abdalla, M., Bellare, M., and P. Rogaway, "DHIES: An encryption scheme based on the Diffie-Hellman Problem", https://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf

## Authors' Addresses

[Author information would be included here in a complete RFC]

## Appendix A: Data Structures and Formats

### A.1. Identity Format

```
+----------------+--------------------------------+
| Type           | Identity-specific data         |
| (1 byte)       | (variable length)              |
+----------------+--------------------------------+
```

### A.2. FIDO2 Signature Format (MessagePack encoded)

```
{
  "s": Uint8Array,  // Signature bytes
  "c": Uint8Array,  // Client data JSON
  "a": Uint8Array   // Authenticator data
}
```

### A.3. VaultysId Fingerprint Format

The fingerprint is a 40-character hexadecimal string derived from:
1. The identity type byte
2. SHA-224 hash of the identity's key material

It is formatted as space-separated groups of 4 characters for readability.

## Appendix B: Implementation Notes

### B.1. Browser Compatibility

The protocol has been tested with:
- Chrome/Edge (full WebAuthn and PRF support)
- Firefox (WebAuthn support, limited PRF support)
- Safari (WebAuthn support, no direct attestation, limited PRF support)

### B.2. Hardware Compatibility

The protocol has been tested with:
- YubiKey (FIDO2 compliant, no PRF support)
- Windows Hello (FIDO2 compliant, PRF support)
- Apple Touch ID (FIDO2 compliant, limited PRF support)

### B.3. Key Derivation Paths

The protocol uses the following BIP32 derivation paths:
- Proof key: `m/1'/0'/{swapIndex}'`
- Signing key: `m/1'/0'/{swapIndex}'/0'`

# Request for Comments: VaultysID Encryption Protocol

## 1. Introduction

This document specifies the VaultysID Encryption Protocol, a secure method for encrypting and decrypting data using the NaCl secretbox authenticated encryption scheme. The protocol is designed to provide confidentiality, integrity, and authenticity for file encryption while supporting both local and remote key derivation.

### 1.1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.2. Abbreviations

* PRF: Pseudo-Random Function
* HMAC: Hash-based Message Authentication Code
* VID: VaultysID

## 2. Protocol Overview

The VaultysID Encryption Protocol provides secure file encryption with the following features:

1. Strong authenticated encryption using NaCl secretbox (XSalsa20-Poly1305)
2. Identity-based encryption keys derived from VaultysID credentials
3. Support for both local and remote key derivation
4. Deterministic file format with versioning
5. Support for both whole-file and streaming encryption modes

## 3. Cryptographic Components

### 3.1. Encryption Method

The protocol uses NaCl secretbox, which provides authenticated encryption using:
- XSalsa20 stream cipher for encryption
- Poly1305 for authentication

This combination provides confidentiality, integrity, and authenticity.

### 3.2. Key Derivation

Encryption keys are derived through a two-step process:

1. Generate a PRF value based on the user's VaultysID and a random nonce
2. Apply SHA-256 to the PRF to create a 32-byte encryption key

This approach ensures the encryption key is deterministically derived from the user's identity while remaining unique for each encryption operation.

## 4. File Format Specification

### 4.1. Header Format

Every encrypted file begins with a fixed 32-byte header with the following structure:

```
+----------------+----------------+----------------+
| Magic String   | Version Number | Reserved       |
| (18 bytes)     | (8 bytes)      | (6 bytes)      |
+----------------+----------------+----------------+
```

- Magic String: The ASCII string "vaultys/encryption" (18 bytes)
- Version Number: 64-bit unsigned big-endian integer (8 bytes)
- Reserved: Zero-filled bytes reserved for future use (6 bytes)

The full header in hexadecimal for version 1 is:
```
7661756c7479732f656e6372797074696f6e00000000000000010000000000000000
```

### 4.2. Whole-File Encryption Format

The complete encrypted file structure is:

```
+----------------+----------------+----------------+----------------+----------------+
| Header         | PRF Nonce      | Encryption     | Encrypted Data | Authentication |
| (32 bytes)     | (32 bytes)     | Nonce (24 B)   | (variable)     | Tag (16 bytes) |
+----------------+----------------+----------------+----------------+----------------+
```

- Header: As defined in section 4.1
- PRF Nonce: 32-byte random value used for PRF derivation
- Encryption Nonce: 24-byte nonce used by NaCl secretbox
- Encrypted Data: The encrypted content
- Authentication Tag: Poly1305 authentication tag (implicitly included in NaCl secretbox output)

### 4.3. Chunked Encryption Format

For streaming or chunked encryption, the format is:

```
+----------------+----------------+----------------+
| Header         | PRF Nonce      | Chunks...      |
| (32 bytes)     | (32 bytes)     | (variable)     |
+----------------+----------------+----------------+

Where each chunk has the format:
+----------------+----------------+----------------+
| Encryption     | Encrypted Data | Authentication |
| Nonce (24 B)   | (variable)     | Tag (16 bytes) |
+----------------+----------------+----------------+
```

- Each chunk contains its own encryption nonce
- The recommended chunk size is 64 KB of plaintext data
- The final chunk MAY be smaller than the recommended chunk size

## 5. Encryption Process

### 5.1. PRF Generation

1. Generate a 32-byte random PRF nonce
2. Derive the PRF by one of two methods:
   a. Local: `prf = HMAC(VID_key, "encryption/prf|" + prf_nonce_hex + "|prf/encryption")`
   b. Remote: Request PRF via secure channel using `"encryption/" + prf_nonce_hex + "/encryption"`
3. Verify the PRF is exactly 32 bytes

### 5.2. Key Derivation

1. Derive the encryption key: `key = SHA-256(prf)`
2. Securely erase the PRF value from memory

### 5.3. Whole-File Encryption

1. Generate a 24-byte random encryption nonce
2. Encrypt the plaintext: `ciphertext = nacl.secretbox(plaintext, nonce, key)`
3. Construct the encrypted file as specified in section 4.2
4. Securely erase the key from memory

### 5.4. Chunked Encryption

1. Write the header and PRF nonce
2. For each chunk:
   a. Generate a unique encryption nonce (MAY be derived from chunk number)
   b. Encrypt the chunk: `encrypted_chunk = nacl.secretbox(chunk, nonce, key)`
   c. Write the nonce and encrypted chunk
3. Securely erase the key from memory

## 6. Decryption Process

### 6.1. Header Verification

1. Read the 32-byte header
2. Verify the magic string equals "vaultys/encryption"
3. Extract the version number (current supported version is 1)

### 6.2. PRF Retrieval

1. Read the 32-byte PRF nonce
2. Retrieve the PRF by one of two methods:
   a. Local: `prf = HMAC(VID_key, "encryption/prf|" + prf_nonce_hex + "|prf/encryption")`
   b. Remote: Request PRF via secure channel using `"encryption/" + prf_nonce_hex + "/encryption"`
3. Verify the PRF is exactly 32 bytes

### 6.3. Key Derivation

1. Derive the decryption key: `key = SHA-256(prf)`
2. Securely erase the PRF value from memory

### 6.4. Whole-File Decryption

1. Read the 24-byte encryption nonce
2. Read the encrypted data
3. Decrypt: `plaintext = nacl.secretbox.open(ciphertext, nonce, key)`
4. If decryption fails, abort and return an error
5. Securely erase the key from memory

### 6.5. Chunked Decryption

1. For each chunk:
   a. Read the 24-byte encryption nonce
   b. Read the encrypted chunk
   c. Decrypt: `plaintext_chunk = nacl.secretbox.open(encrypted_chunk, nonce, key)`
   d. If decryption fails, abort and return an error
2. Concatenate all plaintext chunks
3. Securely erase the key from memory

## 7. Security Considerations

### 7.1. Nonce Uniqueness

The security of XSalsa20 depends on nonce uniqueness. The protocol ensures this by:
- Using random 24-byte nonces for whole-file encryption
- Using deterministic nonces derived from chunk numbers for chunked encryption
- Using 32-byte PRF nonces to ensure unique keys for each encryption operation

### 7.2. Key Management

- Encryption keys MUST be 32 bytes long
- Keys MUST be securely erased from memory after use
- The PRF value MUST be securely erased after key derivation

### 7.3. Error Handling

- Implementations MUST NOT reveal information about decryption failures beyond indicating that an error occurred
- Any tampering with the ciphertext will cause authentication to fail, and implementations MUST reject such data

### 7.4. Forward Secrecy

This protocol does not provide forward secrecy. If a VaultysID is compromised, all files encrypted with that identity may be decrypted.

## 8. Implementation Considerations

### 8.1. Streaming vs. Whole-File

- Whole-file encryption is simpler but requires keeping the entire file in memory
- Streaming encryption is more complex but allows handling files larger than available memory
- Implementations SHOULD support both modes where appropriate

### 8.2. Progress Reporting

- Implementations SHOULD provide progress reporting for large files
- For chunked encryption/decryption, progress can be reported per chunk

### 8.3. Error Propagation

- Stream-based implementations MUST properly propagate errors to the application
- If one chunk fails to decrypt, the entire file SHOULD be considered compromised

## 9. Examples

### 9.1. Example Header (Hexadecimal)

For version 1:
```
7661756c7479732f656e6372797074696f6e00000000000000010000000000000000
```

For version 2:
```
7661756c7479732f656e6372797074696f6e00000000000000020000000000000000
```

### 9.2. PRF Derivation String Examples

Local PRF derivation string for nonce "a1b2c3d4...":
```
encryption/prf|a1b2c3d4...|prf/encryption
```

Remote PRF request path for nonce "a1b2c3d4...":
```
encryption/a1b2c3d4.../encryption
```

## 10. Interoperability Considerations

### 10.1. Versioning

- Implementations MUST reject files with unsupported version numbers
- Future versions MAY add additional fields or change encryption methods, but MUST maintain the same header format

### 10.2. Cross-Platform Issues

- Implementations MUST handle binary data correctly, especially when transmitting between platforms with different endianness
- All multi-byte integers MUST be encoded in big-endian format

## 11. References

### 11.1. Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

[NACL] Bernstein, D.J., et al., "Networking and Cryptography library", https://nacl.cr.yp.to/

### 11.2. Informative References

[XSALSA20] Bernstein, D.J., "Extending the Salsa20 nonce", https://cr.yp.to/snuffle/xsalsa-20110204.pdf

[POLY1305] Bernstein, D.J., "The Poly1305-AES message-authentication code", https://cr.yp.to/mac/poly1305-20050329.pdf

## Appendix A: Test Vectors

[Test vectors would be included here in a complete RFC]

## Appendix B: Code Examples

[Code examples would be included here in a complete RFC]

## Authors' Addresses

[Author information would be included here in a complete RFC]

# Request for Comments: Vaultys Web of Trust Protocol

## 1. Introduction

This document specifies the Vaultys Web of Trust Protocol, a secure mechanism for establishing trust relationships between entities using the Vaultys Decentralized Identity Keyring. The protocol enables mutual authentication, relationship certification, and cryptographic proofs of connection, forming the foundation for a decentralized web of trust.

### 1.1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.2. Abbreviations

* WoT: Web of Trust
* DID: Decentralized Identifier
* SRP: Secure Remote Protocol (in this context, refers to Signing Remote Protocol)
* PRF: Pseudo-Random Function

## 2. Protocol Overview

The Vaultys Web of Trust Protocol provides a mechanism for establishing verifiable trust connections between identity holders through the following features:

1. Challenge-based mutual authentication
2. Protocol-specific challenge context (protocol/service designation)
3. Timestamped and liveliness-verified exchanges
4. Non-repudiable cryptographic signatures
5. Certificate generation and validation
6. Metadata exchange
7. Channel-based secure communications

## 3. Challenge Format

### 3.1. Challenge Structure

The challenge is the core element of the trust establishment protocol. It is encoded using MessagePack and contains the following fields:

```
{
  "protocol": string,      // Protocol identifier
  "service": string,       // Service identifier
  "timestamp": number,     // Unix timestamp
  "pk1": Buffer,           // Public key of initiator
  "pk2": Buffer,           // Public key of responder
  "nonce": Buffer,         // Random nonce (16 bytes initially, 32 bytes complete)
  "sign1": Buffer,         // Signature from initiator
  "sign2": Buffer,         // Signature from responder
  "metadata": object,      // Optional context-specific metadata
  "state": number          // Protocol state
}
```

### 3.2. Protocol States

The challenge progresses through the following states:

| State Value | State Name      | Description                                    |
|-------------|-----------------|------------------------------------------------|
| -2          | ERROR           | Protocol failed with an error                  |
| -1          | UNINITIALISED   | Challenge not yet initialized                  |
| 0           | INIT            | Challenge created, not yet sent                |
| 1           | STEP1           | Response received from second party            |
| 2           | COMPLETE        | Both signatures verified, challenge complete   |

## 4. Trust Establishment Protocol

### 4.1. Challenge Creation and Exchange

The trust establishment follows a three-step exchange:

1. **Initiator creates challenge**:
   - Generates random nonce (16 bytes)
   - Sets protocol, service, and timestamp
   - Includes initiator's public key (pk1)

2. **Responder processes challenge**:
   - Verifies liveliness of timestamp
   - Extends nonce with additional random 16 bytes (total 32 bytes)
   - Adds responder's public key (pk2)
   - Signs the challenge data (sign2)

3. **Initiator completes challenge**:
   - Verifies responder's signature
   - Adds initiator's signature (sign1)
   - Challenge is now complete

### 4.2. Challenge Verification

Each party verifies the other's signature using the following process:

1. Extract the unsigned challenge data (protocol, service, timestamp, pk1, pk2, nonce)
2. Verify that the signature corresponds to the hash of this data
3. Verify that the signature is valid for the counterparty's public key

### 4.3. Liveliness Verification

To prevent replay attacks, all challenges include liveliness verification:

```
isLive(challenge, liveliness, time) {
  return challenge.timestamp > time - liveliness &&
         challenge.timestamp < time + liveliness;
}
```

Where `liveliness` defines the acceptable time window (default 60 seconds).

## 5. Certificate Generation and Storage

### 5.1. Certificate Format

A completed challenge is serialized into a certificate that serves as cryptographic proof of the connection. The certificate contains all challenge fields and is stored in the participants' local databases.

### 5.2. Certificate Verification

Certificates can be independently verified by third parties using the public keys and signatures they contain:

```
static async verifyCertificate(certificate: Buffer) {
  const deser = deserialize(certificate);
  return deser.state === COMPLETE;
}
```

## 6. Protocol-Specific Services

The protocol supports different service types within the challenge context:

### 6.1. Authentication Service (`auth`)

Establishes mutual authentication and identity verification between two parties.

### 6.2. Self-Authentication Service (`selfauth`)

Verifies that two devices belong to the same identity owner.

### 6.3. File Signing Service (`signfile`)

Enables requesting and providing cryptographic signatures for files.

### 6.4. Transfer Service (`transfer`)

Establishes a secure channel for data transfer between parties.

### 6.5. Decryption Service (`decrypt`)

Enables secure request and provision of decryption services.

### 6.6. PRF Service (`prf`)

Enables secure generation and exchange of PRF values for derived keys.

## 7. Secure Channel Communication

### 7.1. Channel Interface

The protocol operates over an abstract Channel interface with the following methods:

```typescript
interface Channel {
  start(): Promise<void>;
  close(): Promise<void>;
  send(data: Buffer): Promise<void>;
  receive(): Promise<Buffer>;
  onConnected(callback: () => void): void;
  getConnectionString(): string;
  fromConnectionString(conn: string, options?: any): Channel | null;
}
```

### 7.2. Channel Types

The implementation supports multiple channel types:

1. **MemoryChannel**: In-process communication channel
2. **Encrypted Channel**: Channel with added encryption layer

### 7.3. Stream Support

The protocol provides stream-based operations through the StreamChannel wrapper:

```typescript
interface StreamChannel {
  getReadStream(): Readable;
  getWriteStream(): Writable;
  upload(stream: Readable): Promise<void>;
  uploadData(data: Buffer): Promise<void>;
  download(stream: Writable): Promise<void>;
  downloadData(): Promise<Buffer>;
}
```

## 8. Web of Trust Operations

### 8.1. Contact Management

The protocol enables managing trusted contacts:

```typescript
// Save a contact to the local contact store
saveContact(contact: VaultysId)

// Get a contact by DID
getContact(did: string): VaultysId | null

// Get all contacts
get contacts(): VaultysId[]
```

### 8.2. Certificate Management

Certificates from completed challenges are stored in the local WoT store:

```typescript
// List all certificates in the local WoT
listCertificates(): ChallengeType[]

// Verify a specific certificate
verifyRelationshipCertificate(did: string): Promise<boolean>
```

### 8.3. Contact Metadata

The protocol supports attaching and retrieving metadata for contacts:

```typescript
// Set metadata for a contact
setContactMetadata(did: string, name: string, value: any)

// Get specific metadata for a contact
getContactMetadata(did: string, name: string): any

// Get all metadata for a contact
getContactMetadatas(did: string): object | null
```

## 9. Cross-Device Operations

### 9.1. Device Synchronization

The protocol supports synchronizing data across devices belonging to the same identity:

```typescript
async sync(channel: Channel, initiator = false)
```

During synchronization:
1. Devices authenticate using the `selfauth` service
2. Data is exchanged between devices
3. Contact lists and metadata are merged

### 9.2. Device Verification

Devices can verify they belong to the same identity:

```typescript
// Deprecated - use sync instead
async askMyself(channel: Channel): Promise<boolean>
async acceptMyself(channel: Channel): Promise<boolean>
```

## 10. Secure Remote Services

### 10.1. Remote PRF Generation

The protocol enables requesting PRF values from remote devices:

```typescript
async requestPRF(channel: Channel, appid: string): Promise<Buffer>
async acceptPRF(channel: Channel, accept?: (contact: VaultysId, appid: string) => Promise<boolean>)
```

### 10.2. Remote File Operations

The protocol supports secure file encryption, decryption, and signing:

```typescript
// Remote file encryption/decryption
async requestEncryptFile(channel: Channel, toEncrypt: File): Promise<File | null>
async requestDecryptFile(channel: Channel, toDecrypt: File): Promise<File | null>

// Remote file signing
async requestSignFile(channel: Channel, file: File): Promise<FileSignature | undefined>
```

## 11. Security Considerations

### 11.1. Replay Attacks

To prevent replay attacks:
- Challenges include timestamps
- Liveliness verification ensures timestamps are within an acceptable window
- Nonces are used to ensure uniqueness

### 11.2. Man-in-the-Middle Attacks

The protocol mitigates man-in-the-middle attacks through:
- Mutual authentication
- Cryptographic signatures
- Certificate verification

### 11.3. Key Compromise

If a key is compromised:
- Existing certificates remain valid
- New certificates can be issued with updated keys
- A revocation mechanism should be employed

## 12. Examples

### 12.1. Establishing a New Contact Relationship

```typescript
// Device A (Initiator)
const contactA = await idManagerA.askContact(channel);

// Device B (Responder)
const contactB = await idManagerB.acceptContact(channel);

// Both devices now have a verified contact with a certificate
console.log(contactA.did === idManagerB.vaultysId.did); // true
console.log(contactB.did === idManagerA.vaultysId.did); // true
```

### 12.2. Verifying a File Signature

```typescript
// Request a file signature
const fileSignature = await idManager.requestSignFile(channel, file);

// Verify the signature
const isValid = idManager.verifyFile(file, fileSignature, contact);
```

### 12.3. Remote File Encryption

```typescript
// Request file encryption from a remote device
const encryptedFile = await idManager.requestEncryptFile(channel, file);

// Request file decryption from a remote device
const decryptedFile = await idManager.requestDecryptFile(channel, encryptedFile);
```

## 13. Protocol Message Flow

### 13.1. Contact Establishment Flow

```
Initiator                                 Responder
    |                                        |
    |-- Create challenge ----------------->  |
    |   (protocol, service, pk1, nonce)      |
    |                                        |
    |                                        |-- Process challenge
    |                                        |   Add pk2, extend nonce
    |                                        |   Sign challenge
    |                                        |
    |  <------------------- Return challenge |
    |                      (pk1, pk2, sign2) |
    |                                        |
    |-- Verify sign2 ----------------------> |
    |   Sign challenge                       |
    |                                        |
    |  <------------------- Complete challenge
    |                   (pk1, pk2, sign1, sign2)
    |                                        |
    |-- Store certificate --------------->   |
    |                                        |-- Store certificate
    |                                        |
```

### 13.2. PRF Request Flow

```
Requester                                  Provider
    |                                        |
    |-- Establish contact (SRP) ---------->  |
    |                                        |
    |  <---------------------- Contact established
    |                                        |
    |-- Send appid ------------------------> |
    |                                        |
    |                                        |-- Verify appid
    |                                        |   Generate PRF
    |                                        |
    |  <----------------------------- Send PRF
    |                                        |
```

## 14. References

### 14.1. Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

[MSGPACK] MessagePack, "MessagePack Specification", https://github.com/msgpack/msgpack/blob/master/spec.md

### 14.2. Informative References

[VID-KEYRING] "Vaultys Decentralized Identity Keyring Protocol"

[DID-CORE] W3C, "Decentralized Identifiers (DIDs) v1.0", https://www.w3.org/TR/did-core/

[PGP-WOT] Zimmermann, P., "The Official PGP User's Guide", 1995

## Authors' Addresses

[Author information would be included here in a complete RFC]

## Appendix A: Challenge Serialization Details

### A.1. MessagePack Serialization

Challenges are serialized using MessagePack for compact binary representation. The protocol supports two serialization versions for backward compatibility:

#### A.1.1. Version 0 Serialization (Legacy)

Uses a custom encoding function for challenge fields:

```typescript
const encode_v0 = ({ protocol, service, timestamp, pk1, pk2, nonce, metadata }) => {
  const p = Buffer.concat([
    Buffer.from([0x87]),  // Map with 7 elements
    writeString("protocol", protocol),
    writeString("service", service),
    writeInt("timestamp", timestamp),
    writeBuffer("pk1", pk1),
    writeBuffer("pk2", pk2),
    writeBuffer("nonce", nonce),
    Buffer.from([0xa0 + "metadata".length]),
    Buffer.from("metadata", "ascii"),
    Buffer.from([0x80]), // empty metadata
  ]);
  return p;
};
```

#### A.1.2. Version 1 Serialization (Current)

Uses standard MessagePack encoding:

```typescript
const serialize = (data: ChallengeType) => {
  if (data.state == INIT) {
    const { protocol, service, timestamp, pk1, nonce, metadata } = data;
    const picked = { protocol, service, timestamp, pk1, nonce, metadata };
    const encoded = encode(picked);  // Standard MessagePack encode
    return Buffer.from(encoded);
  }
  // Other states...
};
```

### A.2. Challenge Deserialization

Deserialization includes validation of the challenge structure and state:

```typescript
const deserialize = (challenge: Buffer): ChallengeType => {
  const unpacked = decode(challenge) as ChallengeType;
  // ... validation logic ...
  return result;
};
```

## Appendix B: Certificate Structure

A complete certificate contains:

1. Protocol identifier (e.g., "p2p")
2. Service identifier (e.g., "auth", "selfauth")
3. Timestamp of creation
4. Public keys of both parties (pk1, pk2)
5. Combined nonce (32 bytes)
6. Cryptographic signatures from both parties (sign1, sign2)
7. Optional metadata

Example binary certificate (hex):
```
87a8 7072 6f74 6f63 6f6c a370 3270 a773 6572 7669 6365 a461
7574 68a9 7469 6d65 7374 616d 70ce 612c afc1 a370 6b31 c500
20e5 d15b 7f25 9a45 efdc 75b4 1d8a 0895 b21f e1eb 51de bc01
b74c 13ad db76 b362 a370 6b32 c500 20e5 d15b 7f25 9a45 efdc
75b4 1d8a 0895 b21f e1eb 51de bc01 b74c 13ad db76 b362 a56e
6f6e 6365 c500 208b 4367 8763 efb5 9fe9 2ef8 ca58 57a9 92bd
1c86 1bb0 0c72 a6d9 bae2 e3a2 f3cd a673 6967 6e31 c500 40ce
cd11 0f10 1f66 4fa5 01d8 a1e8 ad80 9a7d ffac 26d6 e29c a2fe
9c6a 36ab 42d5 04ef 9f79 2c80 e67c 7b64 bd50 1e5f 84c6 1429
da29 a6d5 e2a9 aa7e 3fff 7ba6 7369 676e 32c5 0040 dbe6 2c68
7c8d baf8 6ec7 0e16 f1dc 3bf5 62a1 29df dfc1 c4ee 3aba 77ab
9d7c f6ef b318 a583 48b9 c94e 5d1e 34c8 eecc 7cd1 ebce 9a8a
d86b 07aa c8a1 095a 16ac a86d 6574 6164 6174 61a2 6161 01
```

## Appendix C: Implementation Notes

### C.1. Browser Compatibility

The protocol has been tested with:
- Chrome/Edge
- Firefox
- Safari

### C.2. Integration with Existing Systems

The protocol can be integrated with existing identity systems by:
1. Implementing the Channel interface
2. Providing a VaultysId instance
3. Following the challenge-response flow

### C.3. Performance Considerations

- Challenges are typically small (< 1KB)
- Certificate verification is computationally lightweight
- The protocol is suitable for low-bandwidth, high-latency connections

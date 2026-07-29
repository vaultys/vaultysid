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
  "version": integer,     // Protocol wire version: 0 or 1 (see 3.4)
  "protocol": string,     // Protocol identifier
  "service": string,      // Service identifier
  "timestamp": integer,   // Unix timestamp in MILLISECONDS (see 3.3), unsigned
  "pk1": Buffer,          // Public key of initiator
  "pk2": Buffer,          // Public key of responder (absent in INIT)
  "nonce": Buffer,        // Random nonce (16 bytes initially, 32 bytes from STEP1 on)
  "sign1": Buffer,        // Signature from initiator (present only from COMPLETE on)
  "sign2": Buffer,        // Signature from responder (present from STEP1 on)
  "metadata": object,     // Context-specific metadata, always present (MAY be empty)
}
```

`state` is a local/in-memory concept used to drive the protocol state machine (see 3.2); it is NEVER part of the wire encoding. Implementations MUST infer state on receipt from which of `pk2`/`sign1`/`sign2` are present and from `nonce` length (16 bytes = INIT, 32 bytes = STEP1 or COMPLETE), exactly as described in 3.2 and 4.2, not from a transmitted state field.

### 3.1.1. Wire Field Presence Per State

The wire message is NOT a single fixed-shape structure -- fields are only present for the fields that apply to that state, and implementations MUST reproduce this exactly for cross-language byte compatibility (see 3.5):

| Field       | INIT | STEP1 | COMPLETE |
|-------------|:----:|:-----:|:--------:|
| version     |  X   |   X   |    X     |
| protocol    |  X   |   X   |    X     |
| service     |  X   |   X   |    X     |
| timestamp   |  X   |   X   |    X     |
| pk1         |  X   |   X   |    X     |
| pk2         |      |   X   |    X     |
| nonce       |  X   |   X   |    X     |
| sign1       |      |       |    X     |
| sign2       |      |   X   |    X     |
| metadata    |  X   |   X   |    X     |

Field order on the wire MUST be exactly the order shown in this table (top to bottom, skipping absent fields) -- this matches struct/field declaration order in both reference implementations. `metadata` is always last.

### 3.2. Protocol States

The challenge progresses through the following states:

| State Value | State Name      | Description                                    |
|-------------|-----------------|------------------------------------------------|
| -2          | ERROR           | Protocol failed with an error                  |
| -1          | UNINITIALISED   | Challenge not yet initialized                  |
| 0           | INIT            | Challenge created, not yet sent                |
| 1           | STEP1           | Response received from second party            |
| 2           | COMPLETE        | Both signatures verified, challenge complete   |

### 3.3. Timestamp Encoding

`timestamp` MUST be Unix time in **milliseconds** (matching JavaScript's `Date.now()`), and MUST be encoded on the wire as an **unsigned** integer type.

This is not a stylistic preference: it was the root cause of a real, deterministic cross-language interoperability failure. A signed 64-bit MessagePack field (msgpack type `0xd3`) and an unsigned 64-bit field (`0xcf`) produce different bytes for the identical non-negative numeric value. Since `sign1`/`sign2` are computed over the exact serialized bytes of the unsigned challenge (4.2), any implementation that encodes `timestamp` as a signed integer will produce signatures that fail to verify against every other conforming implementation, on every single handshake -- this is not an edge case, it reproduces on every message. See 3.5 and Appendix D for the general rule this falls out of, and `vectors/challenger-handshake-ed25519.json` for a byte-exact vector demonstrating the correct encoding.

### 3.4. Wire Version and a Known Compatibility Gap

`version` (0 or 1) selects the wire format used for `serializeUnsigned` (4.2). **Implementations MUST treat this as a genuinely different byte format, not a metadata flag**: version 0 historically used a bespoke, hand-rolled positional MessagePack encoder (no generic map, no `version` field on the wire at all, and its own idiosyncratic integer-width rules) predating the general MessagePack-map encoding that version 1 (and version 0 in some code paths -- see below) uses.

This has produced real, confirmed divergence between implementations: as of this writing, the TypeScript reference implementation's `serializeUnsigned` still branches internally on `version === 0` to the legacy encoder, while other implementations that have adopted the general MessagePack-map format for all versions do NOT reproduce that legacy byte layout for version 0. **Practical implication: version 0 challenges are not currently guaranteed byte-compatible across implementations.** Until this is resolved (either by every implementation reproducing the legacy v0 encoder exactly, or by deprecating v0 in favor of always negotiating v1), implementations SHOULD default to and prefer version 1, and MUST NOT assume version 0 interoperates cross-language without testing against the specific peer implementation in question. All reference vectors in Appendix D use version 1 for this reason, except where explicitly noted otherwise.

### 3.5. Canonical MessagePack Encoding Requirements

Because `sign1`/`sign2` are verified by independently re-serializing the unsigned challenge and checking the signature against those bytes (4.2) -- never by trusting the raw bytes as received -- **every implementation's serializer MUST produce byte-identical output for the same logical challenge, for every integer field, not just field order.** MessagePack, unlike e.g. JSON, is not canonical by default: a compliant encoder is free to represent the same integer value with different type-tagged widths, and different libraries commonly choose differently. Two encodings observed to diverge in practice between implementations of this protocol:

1. **Signed vs. unsigned tag at the same width** (see 3.3): a 64-bit non-negative value encoded as signed (`0xd3`) vs. unsigned (`0xcf`).
2. **Fixed-width vs. minimal-width integers**: some encoders always use the byte-width of the source language's static type (e.g. a byte value declared as an 8-bit integer type always emits the explicit 1-byte-tag form, `0xcc 0x01`), while others -- including the JavaScript reference implementation -- always emit the smallest MessagePack representation the value fits in regardless of the source type (e.g. `0x01`, a bare positive fixint, with no type tag at all, for the same value).

Implementations MUST encode every integer field (`version`, `timestamp`) using the smallest MessagePack representation the value fits (positive/negative fixint where possible, growing only as needed) and MUST use the unsigned family of MessagePack integer types for fields that are never negative (`timestamp`). A fixed-width or signed-family encoder will produce a technically-valid, correctly-decodable MessagePack message that nonetheless fails every cross-language signature verification, because the bytes actually signed differ from the bytes an unsigned/minimal-width encoder would produce for the same value. `vectors/challenger-handshake-ed25519.json` is a byte-exact demonstration of correct encoding for both `version` and `timestamp`, verified against two independent implementations.

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

#### A.1.1. Version 0 `serializeUnsigned` (Legacy)

The bytes actually signed/verified for version 0 (see 3.4) use a bespoke, hand-rolled positional encoder, NOT the generic MessagePack map encoding described in A.1.2 -- note the field set here has no `version` key at all, and `writeInt`'s width selection does not follow the unsigned/minimal-width rule of 3.5 (this is itself part of why version 0 is flagged as a known compatibility gap in 3.4 -- this encoder predates that rule and has not been consistently reimplemented by every implementation):

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

#### A.1.2. Version 1 Serialization (Current, Recommended)

Uses standard MessagePack map encoding, subject to the canonical-encoding rules in 3.5 (minimal-width, unsigned-family integers). Field order and presence per state follow 3.1.1; the `picked` object below shows the INIT case:

```typescript
const serialize = (data: ChallengeType) => {
  if (data.state == INIT) {
    const { version, protocol, service, timestamp, pk1, nonce, metadata } = data;
    const picked = { version, protocol, service, timestamp, pk1, nonce, metadata };
    const encoded = encode(picked);  // Standard MessagePack encode, minimal-width integers
    return Buffer.from(encoded);
  }
  // STEP1 additionally includes pk2 (after pk1) and sign2 (after nonce);
  // COMPLETE additionally includes sign1 (before sign2). See 3.1.1.
};
```

A conforming non-TypeScript implementation MUST reproduce the *effect* of this encoding (field order, field presence per state, minimal-width unsigned integers) -- it need not use MessagePack's generic "encode any object" API; e.g. the Go reference implementation marshals a tagged struct whose field order and `omitempty` tags are chosen to reproduce this exactly, combined with an encoder option forcing minimal-width integer encoding (3.5). See `vectors/challenger-handshake-ed25519.json` for byte-exact ground truth.

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

- Challenges are typically small (< 1KB) for classical (Ed25519) identities; post-quantum (Dilithium/ML-DSA) identities are two orders of magnitude larger (public keys and signatures are multiple KB each -- see `vectors/challenger-handshake-dilithium.json`) and implementations SHOULD size buffers/transports accordingly rather than assuming a fixed small upper bound
- Certificate verification is computationally lightweight for Ed25519; Dilithium verification is more expensive and larger, though still practical for interactive handshakes
- The protocol is suitable for low-bandwidth, high-latency connections for classical identities; post-quantum identities increase bandwidth requirements substantially

## Appendix D: Reference Vectors

The `rfc/vectors/` directory contains machine-checkable reference vectors generated directly from a reference implementation and, where noted, independently cross-validated against a second implementation. Implementers SHOULD use these to validate their own encoder/signer before attempting live interop testing -- they catch the class of bug described in 3.3/3.5 immediately, without needing a second running implementation to test against.

### D.1. `challenger-handshake-ed25519.json`

A full INIT -> STEP1 -> COMPLETE handshake between two Ed25519 identities, using fixed entropy, nonces, and timestamp so every field is reproducible. **Cross-validated byte-for-byte between the Go and TypeScript reference implementations**, including:
- Identity `id`/DID bytes derived from fixed entropy
- The exact wire bytes for all three messages
- The exact "unsigned" bytes that `sign1`/`sign2` are computed and verified over
- `sign2` produced independently by each implementation being **byte-identical** (Ed25519 signing is deterministic per RFC 8032, so this is a meaningful check, not just "both signatures verify")

This is the vector to check first when porting the protocol to a new language: if your implementation's INIT/unsigned bytes don't match this vector's `wireBytesHex`/`unsignedBytesHex` for the same fixed inputs, your encoding has a bug that will manifest as signature-verification failures against every real peer, exactly as described in 3.3/3.5.

### D.2. `challenger-handshake-dilithium.json`

The same handshake shape, using Dilithium (post-quantum ML-DSA-65) identities. **This vector is currently TypeScript-only**: as of this writing the Go reference implementation has no post-quantum key manager at all, so there is no second implementation to cross-validate against yet (unlike D.1). It is included so a future Go or Rust post-quantum implementation has byte-exact ground truth to match rather than starting from prose. The Rust implementation does have working Dilithium support and an existing TS<->Rust Dilithium interop test path (`interops/run-cross-language-test.sh dilithium`); cross-validating this vector against Rust is a natural next step.

Note the dramatically larger field sizes versus D.1 (public keys ~2.6KB, signatures ~4.6KB) -- see C.3.

### D.3. `dhies.json`

A deterministic vector for the DHIES encrypted-messaging scheme (see RFC ENCRYPTION.md / DHIES.md), fixing the normally-random ephemeral key and nonce so the ciphertext is reproducible. Validated against the real, unmodified decryption function (not a hand-rolled reimplementation on both ends), plus a tamper check (flipping one ciphertext byte MUST be rejected) and an independent production round trip with real randomness.

### D.4. Regenerating Vectors

Each vector has a corresponding generator, kept alongside the reference implementation's own compatibility test tooling:
- `go/test/compatibility/generate_rfc_challenger_vectors.go` (`go run` it; regenerates D.1)
- `go/test/compatibility/generate_rfc_dhies_vector.go` (`go run` it; regenerates D.3)
- `typescript/test/interops/generate-pq-vectors.ts` (`npx tsx` it; regenerates D.2)
- `typescript/test/interops/verify-rfc-vectors.ts` (`npx tsx` it, passing a D.1-shaped vector file path; independently re-derives and checks every byte string in the vector using the TypeScript implementation -- this is the script that produced the D.1 cross-validation claim above)

# Request for Comments: VaultysID DHIES Peer-to-Peer Encryption Protocol

## 1. Introduction

This document specifies the VaultysID DHIES (Diffie-Hellman Integrated Encryption Scheme) protocol, used for authenticated point-to-point encryption between two VaultysID identities' X25519 encryption keys. It is distinct from, and MUST NOT be confused with, the whole-file encryption scheme specified in `ENCRYPTION.md`: DHIES encrypts a message *for a specific recipient identity* using their public key, with no shared secret established out-of-band, whereas `ENCRYPTION.md` encrypts a file using a key derived from the *sender's own* identity (for self-storage, or via a PRF exchange with a remote party over an established channel).

### 1.1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.2. Abbreviations

* DHIES: Diffie-Hellman Integrated Encryption Scheme
* KDF: Key Derivation Function
* MAC: Message Authentication Code

## 2. Protocol Overview

DHIES provides authenticated encryption from a sender to a specific recipient, given only the recipient's static public encryption key (no prior handshake or shared secret required):

1. An ephemeral X25519 keypair is generated per message.
2. A shared secret is derived via X25519 between the ephemeral private key and the recipient's static public key.
3. Separate encryption and MAC keys are derived from that shared secret via a domain-separated SHA-512 KDF.
4. The plaintext is encrypted with XSalsa20-Poly1305 (NaCl `secretbox`).
5. A separate outer SHA-256 MAC additionally authenticates the sender's static public key, binding the ciphertext to the claimed sender identity (not just to the ephemeral key).

Only the recipient (holder of the static private key corresponding to the public key the message was encrypted for) can decrypt. Forward secrecy is provided per-message via the ephemeral key, but NOT for the sender's identity: the outer MAC construction authenticates the claimed sender's static public key, which the caller of `decrypt()` supplies out-of-band (e.g. from an already-verified contact/DID) -- see Security Considerations 7.2.

## 3. Cryptographic Components

### 3.1. Key Agreement

X25519 Diffie-Hellman is used twice per message on the sender side (once to derive the ephemeral public key from the ephemeral private key, once to derive the shared secret from the ephemeral private key and the recipient's static public key), and once on the recipient side (to derive the same shared secret from their own static private key and the received ephemeral public key).

This raw X25519 output is used directly as KDF input; implementations MUST NOT confuse this with `performDiffieHellman` (used elsewhere in the protocol suite for general-purpose shared-secret derivation), which additionally hashes the raw X25519 output with SHA-256 before returning it. DHIES's own KDF (3.2) performs its own hashing of the raw output; applying `performDiffieHellman`'s extra SHA-256 pass on top would derive different, incompatible keys.

### 3.2. Key Derivation Function

Given the raw shared secret `S`, the sender's static public key `Ps`, and the recipient's static public key `Pr`:

```
context      = "DHIES-KDF" || Ps || Pr
encryptionKey = SHA-512(S || context || 0x01)[0:32]
macKey        = SHA-512(S || context || 0x02)[0:32]
```

Both keys are derived from the same context with only the trailing domain-separation byte differing (`0x01` for encryption, `0x02` for MAC), so a KDF error mixing the two keys up is architecturally impossible to make silently -- they are computed from disjoint hash inputs, not derived via truncation/splitting of one longer output.

The KDF is evaluated identically on both sides: the sender computes it with `(Ps, Pr) = (own static public key, recipient's static public key)`; the recipient computes it with `(Ps, Pr) = (sender's claimed static public key, own static public key)` -- both orderings MUST produce the same `context` bytes, i.e. the sender and recipient roles in the KDF inputs are fixed as (sender, recipient), not (self, other).

### 3.3. Message Authentication

A MAC over the sender's static public key, nonce, and ciphertext (in that order) additionally authenticates the message as coming from the claimed sender, beyond what `secretbox`'s built-in Poly1305 tag already authenticates (the ciphertext alone):

```
MAC = SHA-256(macKey || senderStaticPublicKey || nonce || ciphertext)
```

Implementations MUST compare the received MAC using constant-time comparison, and MUST reject the message without attempting decryption if the MAC does not match (this is checked before, not after, `secretbox` decryption -- see 5.2).

### 3.4. Encryption

`ciphertext = XSalsa20-Poly1305-secretbox(plaintext, nonce, encryptionKey)` (NaCl `secretbox`; nonce is 24 bytes, randomly generated per message). `secretbox`'s own Poly1305 tag is appended by the primitive itself and is included as part of `ciphertext` in the wire format below -- it is a separate authentication layer from the outer MAC in 3.3, not a duplicate of it.

## 4. Wire Format

```
+----------------+------------------------+------------------------+----------------+
| Nonce          | Ephemeral Public Key   | Ciphertext             | MAC            |
| (24 bytes)     | (32 bytes)             | (len(plaintext)+16)    | (32 bytes)     |
+----------------+------------------------+------------------------+----------------+
```

- **Nonce**: 24 random bytes, unique per message, used both as the `secretbox` nonce and as MAC input (3.3).
- **Ephemeral Public Key**: 32-byte X25519 public key, freshly generated per message.
- **Ciphertext**: `secretbox`-encrypted plaintext, `len(plaintext) + 16` bytes (16-byte Poly1305 tag from `secretbox` itself).
- **MAC**: 32-byte SHA-256 outer authentication tag per 3.3.

Total overhead over the plaintext is `24 + 32 + 16 + 32 = 104` bytes.

This exact field layout MUST be reproduced byte-for-byte across implementations -- unlike the Challenger handcheck protocol (see `PROTOCOL.md` 4.2), the recipient never independently reconstructs and re-derives this envelope from named/decoded fields; the layout itself IS the parsing contract, so a reordering (even one that carries the same logical fields) breaks interoperability outright rather than merely breaking a signature check. See `vectors/dhies.json` for a byte-exact reference.

## 5. Encryption and Decryption Process

### 5.1. Encryption

1. Generate a fresh 32-byte ephemeral X25519 private key and derive its public key.
2. Compute the shared secret via X25519(ephemeral private key, recipient's static public key).
3. Derive `encryptionKey`/`macKey` per 3.2, using the sender's own static public key and the recipient's static public key.
4. Generate a fresh 24-byte random nonce.
5. Encrypt: `ciphertext = secretbox(plaintext, nonce, encryptionKey)`.
6. Compute the outer MAC per 3.3 over `senderStaticPublicKey || nonce || ciphertext`.
7. Assemble the wire message per section 4.
8. Securely erase the ephemeral private key, shared secret, and derived keys from memory.

### 5.2. Decryption

Given the wire message and the sender's claimed static public key (supplied by the caller, out-of-band -- see 7.2):

1. Parse `nonce`, `ephemeralPublicKey`, `ciphertext`, `mac` per the fixed layout in section 4.
2. Compute the shared secret via X25519(own static private key, `ephemeralPublicKey`).
3. Derive `encryptionKey`/`macKey` per 3.2, using the sender's claimed static public key and the recipient's own static public key.
4. Recompute the expected MAC per 3.3 and compare it to the received `mac` using constant-time comparison. **MUST fail closed and MUST NOT attempt decryption if this does not match.**
5. Decrypt: `plaintext = secretbox.open(ciphertext, nonce, encryptionKey)`. If this fails (invalid Poly1305 tag), MUST fail closed.
6. Securely erase the shared secret and derived keys from memory.

## 6. Security Considerations

### 6.1. Nonce Uniqueness

`secretbox` (XSalsa20) security depends on nonce uniqueness under a given key. Since `encryptionKey` is fresh per message (derived from a fresh ephemeral key), nonce reuse across messages is not by itself catastrophic the way it would be under a long-term static key, but implementations MUST still generate the nonce with a cryptographically secure random source per message, since the ephemeral-key-derivation chain is the only thing standing between a nonce-reuse bug and full compromise of that message.

### 6.2. Sender Authentication Is Caller-Supplied, Not Self-Certifying

Unlike a signature scheme, DHIES's outer MAC (3.3) authenticates a *claimed* sender public key that the caller of `decrypt()` supplies as a parameter -- it does not, by itself, prove which identity actually sent the message beyond "someone who could compute this MAC, which requires knowing the shared secret with the recipient, used this specific claimed sender key as MAC input." In practice this means: only someone who can derive the correct shared secret (i.e., someone who holds the ephemeral private key -- realistically, the actual sender) could have produced a passing MAC for a given claimed-sender-key input, so the check is meaningful, but callers MUST supply the sender's public key from an already-trusted source (e.g. a verified DID/contact), not from unauthenticated data received alongside the ciphertext. Passing an attacker-supplied "claimed sender key" defeats the authentication property entirely.

### 6.3. Forward Secrecy

Per-message forward secrecy is provided for the *message content*: each message uses a fresh ephemeral key, so compromise of one message's ephemeral private key (which is erased after use, 5.1 step 8) does not expose other messages. This does NOT extend to the recipient's static private key: if the recipient's long-term static private key is later compromised, all past messages encrypted to that static public key can be decrypted (the attacker can replay the X25519 step using the recorded ephemeral public keys from captured ciphertexts). This is standard for DHIES-family schemes and matches the whole-file encryption protocol's equivalent caveat (`ENCRYPTION.md` 7.4).

### 6.4. Error Handling

Implementations MUST NOT reveal whether a MAC mismatch or a `secretbox` decryption failure occurred through distinguishable error messages, timing, or behavior observable by a network attacker -- both MUST be reported identically as an opaque decryption failure.

## 7. References

### 7.1. Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

[NACL] Bernstein, D.J., et al., "Networking and Cryptography library", https://nacl.cr.yp.to/

[RFC7748] Langley, A., Hamburg, M., Turner, S., "Elliptic Curves for Security" (X25519), RFC 7748, January 2016.

### 7.2. Informative References

[VID-PROTOCOL] "Vaultys Web of Trust Protocol" (`PROTOCOL.md`, this repository)

[VID-ENCRYPTION] "VaultysID Encryption Protocol" (`ENCRYPTION.md`, this repository) -- the related but distinct whole-file/self-encryption scheme

## Appendix A: Reference Vector

See `vectors/dhies.json`: a deterministic vector (fixed ephemeral key and nonce, normally random) validated against the real, unmodified decryption implementation, including a tamper-rejection check and an independent production (real-random) round trip. See `PROTOCOL.md` Appendix D.3 for details and regeneration instructions.

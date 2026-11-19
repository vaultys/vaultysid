# Request for Comments: VaultysID X-Wing Secure Channel and Bound Handshake

**Status:** Draft, for review. Implemented in the TypeScript reference implementation (`typescript/src/xwingChannel.ts`), which generates the test vectors of §6. Go (`go/pkg/xwingchannel`) implements the channel and the bound handshake; Rust (`rust/src/xwing_channel.rs`) implements the channel only, as its challenger does not implement the 4.0 handshake yet. Both pass the same vectors.

## 1. Introduction

The handshake (`rfc/PROTOCOL.md`) authenticates two identities but does not derive a session key: data exchanged after it is not cryptographically bound to it (§11.2). `CryptoChannel` encrypts each message with one symmetric key that the caller supplies, the same in both directions, with no sequence number: an active attacker on the transport can replay, reorder, drop or reflect messages, and truncate the stream, without knowing the key.

This document defines:

1. an **X-Wing channel** (§3): an ephemeral post-quantum hybrid key exchange (X-Wing, draft-connolly-cfrg-xwing-kem) followed by encrypted records with one key per direction and strict sequence numbers;
2. a **bound handshake** (§4): the existing VaultysID handshake run inside that channel, where both sides sign the channel binding and the service id, and check the peer's values before signing, so that a handshake cannot be relayed to another session or presented to another service.

Nothing changes in the handshake format or in existing identities; the channel and the binding are opt-in.

### 1.1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

`||` is byte concatenation. `lp(x)` is `u32be(len(x)) || x`; strings are UTF-8. `u64be(n)` is an 8-byte big-endian integer. X-Wing is `ml_kem768_x25519` (public key 1216 bytes, ciphertext 1120 bytes, shared secret 32 bytes, secret key = 32-byte seed).

## 2. Primitives

- X-Wing KEM, draft-connolly-cfrg-xwing-kem (test vectors identical from -05 to -11). Implementations MUST check the official vectors; `@noble/post-quantum` 0.6.1 passes them.
- HKDF-SHA-256 (RFC 5869), SHA-256.
- XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha), 32-byte key, 24-byte nonce, 16-byte tag.

## 3. X-Wing channel

### 3.1. Establishment

```
I: (ek, dk) = X-Wing.KeyGen(seed), seed random (32 bytes), erased after use
I -> R: M1 = 0x01 || 0x01 || ek                       (1218 bytes)
R: (ct, ss) = X-Wing.Encaps(ek)
R -> I: M2 = 0x01 || 0x01 || ct                       (1122 bytes)
I: ss = X-Wing.Decaps(ct, dk)

th      = SHA-256(lp("vaultysid/xwing-channel/v1") || lp(M1) || lp(M2))
prk     = HKDF-Extract(salt = th, IKM = ss)
k_i2r   = HKDF-Expand(prk, "vaultysid/xwing-channel/v1/i2r", 32)
k_r2i   = HKDF-Expand(prk, "vaultysid/xwing-channel/v1/r2i", 32)
binding = SHA-256(lp("vaultysid/xwing-binding/v1") || th)
```

- The first two bytes are the version (`0x01`) and the algorithm (`0x01` = X-Wing + XChaCha20-Poly1305). Any other value, or any other length, is refused (`INVALID_FORMAT`) and the transport is closed.
- The responder MUST refuse a public key the KEM rejects and a zero shared secret (`INVALID_KEY`); the initiator MUST refuse a zero shared secret.
- `th` and `binding` are public. `prk`, `ss`, the seed and the encapsulation randomness MUST be erased.
- Each side waits for the peer's message at most a bounded time (default 30 s); on timeout it closes the transport (`TIMEOUT`).

### 3.2. Records

```
record = 0x01 || 0x01 || u64be(seq) || XChaCha20-Poly1305(k_dir, nonce = 0^16 || u64be(seq), m, aad = 0x01 || 0x01 || u64be(seq))
```

- `k_dir` is `k_i2r` for messages from the initiator and `k_r2i` for messages from the responder: a message reflected to its sender does not decrypt.
- Each direction starts at `seq = 0` and adds 1 per record. The receiver MUST require exactly the next value; anything else (replay, reordering, a dropped record) is refused (`INVALID_SEQUENCE`). With one key per direction and a counter, a nonce is never reused.
- An authentication failure is `AUTH_FAILED`. Every failure closes the channel and erases both keys.
- Overhead: 26 bytes per record.

### 3.3. Limits

- The channel alone is **not authenticated**: anyone can answer M1. It is authenticated only by the bound handshake of §4.
- There is no authenticated end-of-stream message; an application that needs one sends it as a record.

## 4. Bound handshake

The handshake runs inside the channel with `protocol = "p2p"` and `service = "auth"`, as `IdManager.askContact` / `acceptContact`. The `service` field of the challenge keeps naming the operation; the service the connection is for travels in metadata:

| Metadata key | Value |
|---|---|
| `vaultys.channel-binding` | base64 of `binding` (§3.1) |
| `vaultys.service` | canonical service id (`rfc/SERVICE-IDENTITIES.md` §3) |

- **Both** sides put both keys in their own metadata (`pk1` for the initiator, `pk2` for the responder). Caller metadata MUST NOT use these keys (`INVALID_ARGUMENT`).
- The responder checks, on INIT and **before signing STEP1**, that `pk1` carries its own `binding` (`BINDING_MISMATCH`) and its expected service id (`SERVICE_MISMATCH`).
- The initiator checks, on STEP1 and **before signing COMPLETE**, that `pk2` carries its `binding` and its service id. If the caller gave an **expected peer** (an identity the service publishes, or the one pinned at the first connection), the initiator also checks that the identity which signed STEP1 has the same fingerprint, `SHA-256` of its version-1 serialized id (`PEER_MISMATCH`).
- On any failure the side sends a single `0` byte, closes the channel and stores nothing. The contact and certificate are stored only after COMPLETE.
- The service id MUST already be canonical; implementations MUST refuse, not normalize, another spelling (`INVALID_SERVICE_ID`).
- Certificates are stored in `wot` under `<timestamp>-<hex SHA-256(certificate)>`, so two handshakes completed in the same millisecond do not overwrite each other.

What this gives: a handshake made in one channel cannot be replayed or relayed into another channel (the binding differs), and a certificate made for one service cannot be presented as one for another (the service id is signed by both). Without an expected peer, the initiator still has to check who the responder is; the responder always learns the initiator's identity from INIT.

## 5. Security considerations

- **Harvest now, decrypt later.** Session keys depend on X-Wing, which stays secure while either ML-KEM-768 or X25519 does.
- **Forward secrecy.** The key pair of M1 is ephemeral and erased after decapsulation; identity keys are never used for encryption, so their later compromise does not reveal past sessions.
- **Authentication is classical or post-quantum depending on the identities.** The handshake signatures are those of the identities (Ed25519, ML-DSA-87 or hybrid).
- **No identity hiding against an active attacker.** The initiator's identity is revealed to whoever answers M1.

## 6. Test vectors

`typescript/test/interops/xwing-draft-vectors.json` holds the official X-Wing vectors (copied unchanged from github.com/dconnolly/draft-connolly-cfrg-xwing-kem, `spec/test-vectors.json`). `typescript/test/interops/generate-xwing-channel-vectors.ts` (`pnpm test:channel:vectors`) writes `xwing-channel-vectors.json`: seeds, M1, M2, shared secret, `th`, both keys, `binding`, and three records in each direction.

# Request for Comments: VaultysID Post-Quantum Identities and Encryption

**Status:** Draft, for review. Nothing in this document is implemented yet.

## 1. Introduction

VaultysID identities backed by Dilithium or Hybrid key managers sign with ML-DSA, but all of their secret-keyed operations still depend on X25519:

- DHIES v2 messages (`rfc/ENCRYPTION.md` §11) are encrypted with X25519 key agreement only.
- File encryption, app PRFs and the local OTP use HMAC keyed with the X25519 secret key.

Shor's algorithm recovers an X25519 secret key from its public key `e`, and `e` is part of every public identity. An attacker who stores ciphertexts or encrypted files today can therefore decrypt them once a cryptographically relevant quantum computer exists ("harvest now, decrypt later").

This document defines **post-quantum identity types** (§4) that fix both problems for new identities:

1. A deterministic ML-KEM-768 key pair, derived from the key-manager seed (§3.1) and published in a new identity field `k` (§4.3).
2. A PRF/HMAC key derived from the seed instead of the X25519 secret (§3.2).
3. DHIES v3, a hybrid message encryption that stays confidential as long as **either** X25519 **or** ML-KEM-768 is unbroken (§5).

Existing identities are unchanged. §6 and §7 describe how old and new identities interoperate.

### 1.1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

`||` is byte concatenation. `SHA-256`, `SHA-512` are as in FIPS 180-4, `HMAC-SHA256` as in RFC 2104. Strings in quotes are ASCII without a terminator.

### 1.2. Notation

| Symbol | Meaning |
|--------|---------|
| `seed` | The 64-byte secret seed `s` of a Dilithium or Hybrid key manager |
| `S_sk`, `S_pk` | Sender's static X25519 key pair (identity field `e`) |
| `R_sk`, `R_pk` | Recipient's static X25519 key pair (identity field `e`) |
| `R_dk`, `R_ek` | Recipient's ML-KEM-768 decapsulation / encapsulation key (identity field `k`) |
| PQ identity | An identity whose type byte has the `0x10` flag set (§4.1) |
| Classical identity | Any other identity, including Dilithium and Hybrid identities of types 0–2 |

## 2. Primitive

The KEM is **ML-KEM-768** as specified in FIPS 203:

| Value | Size (bytes) |
|-------|--------------|
| Encapsulation key `ek` | 1184 |
| Decapsulation key `dk` | 2400 |
| Ciphertext `kem_ct` | 1088 |
| Shared secret `kss` | 32 |

ML-KEM-768 targets NIST security category 3, above the ~128-bit classical strength of X25519, while keeping identity and ciphertext sizes moderate. ML-KEM-1024 was considered and rejected: it adds ~400 bytes to every identity and ciphertext for no practical gain alongside an X25519 component.

## 3. Key Derivation

All keys of a PQ identity are derived from the 64-byte key-manager `seed`. The secret export formats (`{v, s}` for Dilithium, `{v, alg: "hybrid", s}` for Hybrid) are unchanged.

### 3.1. ML-KEM key pair

```
dz          = SHA-512("VAULTYS_MLKEM768_KEYGEN" || seed)     ; 64 bytes
(ek, dk)    = ML-KEM-768.KeyGen_internal(d = dz[0:32], z = dz[32:64])
```

`KeyGen_internal(d, z)` is the deterministic key generation of FIPS 203 §6.1. Libraries expose it as key generation from the 64-byte seed `d || z`: noble `ml_kem768.keygen(dz)`, libcrux `mlkem768::generate_key_pair(dz)`, circl `mlkem768.NewKeyFromSeed(dz)`.

`dk` is never serialized. Implementations re-derive it from `seed` when decrypting and SHOULD erase `dz` and `dk` after use.

### 3.2. PRF/HMAC key

PQ identities key their HMAC-based operations with a seed-derived key instead of the X25519 secret key:

```
prf_key = SHA-512("VAULTYS_PRF_KEY" || seed)[0:32]
```

The following operations change for PQ identities; their inputs and outputs are otherwise identical:

| Operation | Classical identity | PQ identity |
|-----------|-------------------|-------------|
| `hmac(message)`: file encryption PRF, remote PRF (`requestPRF`), app PRF | `HMAC-SHA256(X25519 secret, "VaultysID/" \|\| message \|\| "/end")` | `HMAC-SHA256(prf_key, "VaultysID/" \|\| message \|\| "/end")` |
| `getSecretHash(data)`: local OTP (`getOTPHmac`) | `SHA-256(data \|\| "secrethash" \|\| X25519 secret)` | `SHA-256(data \|\| "secrethash" \|\| prf_key)` |

The file encryption format of `rfc/ENCRYPTION.md` §4 is unchanged: only the key behind the PRF changes. Which key is used depends solely on the type byte of the identity that computes the PRF.

### 3.3. Why derive from the full seed

Neither key may be derived from a value that a quantum adversary can recover from a classical public key. In particular they MUST NOT be derived from:

- the X25519 secret key, or `seed[32:64]` from which it is computed: recoverable from `e`;
- an Ed25519 secret key: recoverable from the Ed25519 public key.

The full `seed` is safe because `seed[0:32]` only feeds ML-DSA key generation, which is one-way even for a quantum adversary. The distinct labels keep the ML-KEM key, the PRF key, the ML-DSA key and the X25519 key independent of one another.

### 3.4. Other key managers (not covered by this draft)

Ed25519, FIDO2 and FIDO2PRF key managers hold no secret that survives a quantum adversary: their stored or PRF-derived secrets are the Ed25519 and X25519 keys themselves. They cannot back a PQ identity under this draft. Possible future extensions:

- Ed25519 / FIDO2: a new secret field holding 64 random bytes, used in place of `seed` in §3.1 and §3.2.
- FIDO2PRF: a second PRF evaluation (`prf.eval.second`) with a distinct salt such as `"VaultysID KEM salt"`, hashed as in §3.1 and §3.2. Types `0x13` and `0x14` are reserved for these (§4.1).

Identities of these types can still **send** DHIES v3 messages to a PQ identity (§5.4).

## 4. Post-Quantum Identity Types

### 4.1. Type byte

The identity type byte gains a post-quantum flag:

```
type = 0x10 | role
```

| Value | Type | Key manager |
|-------|------|-------------|
| `0x10` | PQ MACHINE | Dilithium or Hybrid |
| `0x11` | PQ PERSON | Dilithium or Hybrid |
| `0x12` | PQ ORGANIZATION | Dilithium or Hybrid |
| `0x13` | reserved: PQ FIDO2 | (§3.4) |
| `0x14` | reserved: PQ FIDO2PRF | (§3.4) |

`role = type & 0x0F` keeps the meaning of types 0–4 (`rfc/DID.md` §3.1). Every role check (machine, person, organization, hardware) MUST be computed on `role`, not on the raw type byte. For example, `isMachine()` is `(type & 0x0F) == 0`.

The `0x10` flag means "this identity has an ML-KEM key and a seed-derived PRF key". It says nothing about the signature scheme: both Dilithium (ML-DSA only) and Hybrid (Ed25519 + ML-DSA) key managers are allowed. Identities with types 0–2 keep their current meaning, whatever their key manager.

### 4.2. Parsing and dispatch

For a PQ identity, `fromId()`:

1. Rejects types `0x13`, `0x14` and any other value not listed in §4.1.
2. Decodes the MessagePack record after the type byte.
3. Selects the key manager from the length of `x`: 2592 bytes is Dilithium, 2624 bytes is Hybrid. Any other length MUST be rejected; in particular an Ed25519 key manager MUST NOT appear under a PQ type.
4. Requires `v == 1`, an `e` of 32 bytes, and a `k` of 1184 bytes.

`fromSecret()` follows the same rule: the type byte selects the PQ path, and the secret record selects Dilithium or Hybrid as it does today.

For reference, full serialized lengths including the type byte are 3827 bytes (Dilithium) and 3859 bytes (Hybrid). Implementations SHOULD NOT dispatch on these lengths.

Library versions that predate this document reject the new type bytes before parsing: TypeScript (`unknown identity type`), Rust (`Error::InvalidType`) and Go (`invalid identity type`).

### 4.3. Serialization

The key-manager record of a PQ identity has four fields, encoded in this order:

```
{
  "v": 1,                  // version, MUST be 1
  "x": signingKey,         // ML-DSA-87 (2592 B) or Ed25519 || ML-DSA-87 (2624 B)
  "e": encryptionKey,      // X25519, 32 bytes
  "k": kemKey              // ML-KEM-768 encapsulation key, 1184 bytes (MessagePack bin 16)
}
```

`k` MUST equal the key derived in §3.1. An implementation holding the secret SHOULD check this on load and reject a mismatch.

Implementations that store contacts as key-manager fields rather than as serialized ids (TypeScript `instanciateContact` / `instantiate()`) MUST store and restore `k`. Otherwise a reloaded contact loses its ML-KEM key and can no longer receive DHIES v3.

### 4.4. DID, fingerprint and DID document

The DID and fingerprint keep their definition, `type || SHA-224(keyManager.id)`. Because both the type byte and `k` are covered, a PQ identity always has a different DID from any classical identity, and its DID commits to its ML-KEM key.

The DID document SHOULD list `k` as an additional key agreement method:

```json
{
  "id": "<did>#keys-3",
  "type": "MLKEM768KeyAgreementKey2025",
  "controller": "<did>",
  "publicKeyMultibase": "m<base64 of k>"
}
```

### 4.5. Migrating an existing identity

A classical identity cannot become a PQ identity in place: its DID would change and its PRF key would change, which would make files it already encrypted undecryptable.

To migrate, the owner creates a new PQ identity and links it to the old one with a swapping certificate (`rfc/DID.md` §8.1). The new identity SHOULD be generated from fresh entropy. The old identity remains usable for decrypting what was encrypted to it or by it.

## 5. DHIES v3 (Hybrid Message Encryption)

DHIES v3 extends DHIES v2 with an ML-KEM-768 encapsulation to the recipient. The X25519 sender-to-recipient term `ss` is kept so the recipient can still authenticate the sender.

### 5.1. Inputs

- `S_sk`, `S_pk`: sender's static X25519 key pair (any identity type)
- `R_pk`, `R_ek`: recipient's X25519 key and ML-KEM-768 key (the recipient MUST be a PQ identity)

### 5.2. Encryption

```
(e_sk, e_pk)   = fresh X25519 key pair
es             = X25519(e_sk, R_pk)
ss             = X25519(S_sk, R_pk)                  ; abort if es or ss is all zeros
(kem_ct, kss)  = ML-KEM-768.Encaps(R_ek)
info           = "VAULTYS_DHIES_V3" || e_pk || S_pk || R_pk || SHA-256(R_ek) || kem_ct
k              = SHA-512(es || ss || kss || info)[0:32]
nonce          = 24 random bytes
ct             = XSalsa20-Poly1305 secretbox(plaintext, nonce, k)
out            = 0x03 || nonce || e_pk || kem_ct || ct
```

Layout:

```
+------+------------+------------+----------------+-----------------------+
| 0x03 | Nonce      | e_pk       | kem_ct         | secretbox ciphertext  |
| 1 B  | 24 B       | 32 B       | 1088 B         | len(plaintext) + 16 B |
+------+------------+------------+----------------+-----------------------+
```

The overhead is 1161 bytes per message, against 73 for v2.

### 5.3. Decryption

Given `out`, the recipient's keys and the expected sender public key `S_pk`:

1. Reject unless `len(out) >= 1161` and `out[0] == 0x03`.
2. Parse `nonce = out[1:25]`, `e_pk = out[25:57]`, `kem_ct = out[57:1145]`, `ct = out[1145:]`.
3. Compute `es = X25519(R_sk, e_pk)` and `ss = X25519(R_sk, S_pk)`, rejecting all-zero outputs.
4. Compute `kss = ML-KEM-768.Decaps(R_dk, kem_ct)`. ML-KEM uses implicit rejection: an invalid `kem_ct` yields a pseudorandom `kss` rather than an error, and the secretbox check in step 5 then fails.
5. Derive `k` as in §5.2 and open the secretbox.

Any failure MUST be reported as the same generic decryption error, without distinguishing which step failed.

### 5.4. Version selection

- A sender MUST use DHIES v3 when the recipient is a PQ identity, and DHIES v2 otherwise.
- The sender does not need to be a PQ identity. Any identity with an X25519 key `e` can send v3.
- A PQ identity MUST reject DHIES v2 messages addressed to it. Because only the holder of `S_sk` can produce a valid message, and a PQ recipient is always recognizable from its type byte, this removes any downgrade path.
- Decryption dispatches on the first byte: `0x02` → `rfc/ENCRYPTION.md` §11 (classical recipients only), `0x03` → this section (PQ recipients only).

### 5.5. Design rationale

- **Combiner.** All three secrets and the full transcript are hashed together, so `k` stays secret if either X25519 (`es`) or ML-KEM (`kss`) holds. The ephemeral and recipient X25519 keys appear in `info`, as in X-Wing. `kem_ct` and `SHA-256(R_ek)` are included even though ML-KEM's own transform already binds them, so the security does not depend on ML-KEM ciphertext properties. Hashing them costs ~2 kB of SHA-512 per message.
- **Plain ML-KEM rather than X-Wing.** X-Wing would add a second X25519 key to the identity and duplicate `es`. Reusing the existing `e` keeps the identity 32 bytes smaller and the derivation close to v2.
- **Same symmetric layer as v2.** XSalsa20-Poly1305 with a 256-bit key keeps ~128-bit security against Grover's algorithm, so the symmetric part is unchanged.

## 6. Handshake (SRP) Compatibility

The handshake behind `askContact` / `acceptContact` and the other `startSRP` / `acceptSRP` services (`rfc/PROTOCOL.md`) is algorithm-agnostic: each party verifies the other's signature with the other party's own key manager. Classical identities of different key managers already complete handshakes with each other (verified for Ed25519 ↔ Dilithium, Dilithium ↔ Hybrid and Hybrid ↔ Ed25519).

| | Classical identity | PQ identity |
|---|---|---|
| **Updated library** | Works | Works |
| **Library predating this document** | Works | Refused: the INIT or STEP1 message fails to parse and the handshake ends in `ERROR` |

The challenge format does not change: PQ identities simply appear in `pk1` / `pk2`. Requirements on updated implementations:

1. `fromId()` and the list of known types MUST accept `0x10`–`0x12` (§4.2). The challenger parses `pk1` / `pk2` through `fromId()`.
2. Role checks MUST use `type & 0x0F` (§4.1). Otherwise a PQ machine is refused as an app server and treated as a person when registered as a contact.
3. Stored contacts MUST keep `k` (§4.3).
4. Identity equality compares the type byte, so a classical identity and its PQ successor are distinct contacts. Linking them is the job of the swapping certificate (§4.5).

Each PQ identity adds about 1.2 kB to every handshake message and stored certificate. A COMPLETE certificate between two Hybrid PQ identities (two ids and two Ed25519 + ML-DSA-87 signatures) is about 17 kB. The reference implementations impose no message size limit, but transports carrying handshakes SHOULD allow messages of at least 32 kB.

A relationship certificate is only as strong as its weakest signature: a certificate between a PQ identity and an Ed25519 identity can be forged on the Ed25519 side by a quantum adversary.

## 7. Encryption Compatibility

PQ identities keep their X25519 key `e`, so every encryption feature still works between classical and PQ identities. What changes is which directions are quantum-safe.

### 7.1. Messages (DHIES)

| Sender → recipient | Format | Quantum-safe confidentiality |
|---|---|---|
| Classical → PQ | v3 | Yes |
| PQ → classical | v2 | No |
| PQ → PQ | v3 | Yes |
| Classical → classical | v2 | No (unchanged) |

Protection depends on the **recipient** only. Upgrading one's own identity protects what others send to it, not what it sends to classical identities. A conversation between a classical and a PQ identity is protected in one direction only.

### 7.2. File encryption and PRFs

The PRF is computed by the identity that owns the data (locally, or remotely through `requestPRF`), so the protection follows that identity's type:

| Owner identity | PRF key | Quantum-safe |
|---|---|---|
| Classical | X25519 secret | No |
| PQ | `prf_key` (§3.2) | Yes |

Remote PRF over the handshake works between any pair of identities, because the requesting party never sees the PRF key. Files encrypted by a classical identity stay decryptable only by that identity: migrating to a PQ identity does not re-protect them. Re-encrypting them under the new identity is an application-level decision.

### 7.3. Operations that stay classical

The following keep using X25519 for every identity, including PQ identities, and are out of scope (§8):

- Saltpack (`signcrypt`, `encrypt`, armored `decrypt`). A mixed list of classical and PQ recipients works, but the message is classical even if all recipients are PQ identities.
- `diffieHellman()`, `performDiffieHellman` and the shared OTP `getOTP(remote)`, which derive a key from two static X25519 keys.

## 8. Out of Scope

- **Saltpack**: an X25519-only format with no post-quantum variant. It needs a separate multi-recipient design.
- **Static Diffie-Hellman and the shared OTP**: these require two static keys to agree on a secret without exchanging messages, which a KEM cannot provide.
- **Post-quantum sender authentication** for DHIES (§9.2). Appendix A proposes an optional extension.
- **PQ FIDO2 and FIDO2PRF identities** (§3.4).
- **`CryptoChannel`**: already uses a pre-shared 256-bit symmetric key and is not affected by quantum attacks on X25519.

## 9. Security Considerations

### 9.1. What PQ identities protect

Against an adversary that records data now and later obtains a quantum computer, provided the identity's `seed` stays secret:

- confidentiality of DHIES v3 messages sent to a PQ identity;
- confidentiality of files encrypted through a PQ identity's PRF, and the secrecy of its app PRFs and local OTPs.

### 9.2. What they do not protect

- **DHIES sender authentication is classical.** It relies on `ss`, an X25519 exchange. A quantum adversary can recover `S_sk` from `S_pk` and then forge messages "from" that sender, but only from that point on, and still cannot read past traffic. A post-quantum signature (ML-DSA) over the ciphertext would close this gap at the cost of ~4.6 kB per message and of deniability; Appendix A proposes it as an option.
- **No forward secrecy for the recipient.** Compromising `seed` exposes every message ever sent to that identity, as in v2.
- **Classical identities stay exposed**, including Dilithium and Hybrid identities of types 0–2: their PRFs and their DHIES v2 messages are recoverable from their public `e`. Only migration (§4.5) protects new data.
- **Mixed relationships** are as weak as their classical side (§6, §7).

### 9.3. Key separation

The same `seed` feeds ML-DSA (`seed[0:32]`), X25519 (`seed[32:64]`), ML-KEM (§3.1) and the PRF key (§3.2). Distinct inputs and labels keep these keys independent.

## 10. Open Questions for Review

1. **Seed reuse on migration.** §4.5 recommends fresh entropy. Should deriving the PQ identity from the existing seed be allowed, for users who back up a single secret? The ML-DSA and X25519 keys would then be shared between the old and the new identity.
2. **ML-KEM-768 vs ML-KEM-1024**: this draft picks 768 (§2).
3. **PQ hardware identities** (`0x13`, `0x14`): specify now, or wait until PRF `second` evaluation is reliably available across authenticators.

## 11. Test Vectors

To be generated by the TypeScript reference once implemented, and exported into `go/test/compatibility/testdata` and the Rust compatibility tests.

- **Identity vectors** pin `seed` and the type byte, and give the expected `ek`, `prf_key`, serialized id and DID for Dilithium and Hybrid under each of `0x10`–`0x12`.
- **PRF vectors** pin `seed` and a message, and give the expected `hmac(message)` and `getSecretHash(data)`.
- **DHIES v3 vectors** pin the sender and recipient seeds, the ephemeral X25519 secret key, the 32-byte ML-KEM encapsulation randomness `m` (FIPS 203 `Encaps_internal`; noble `encapsulate(ek, m)`, libcrux `mlkem768::encapsulate(ek, m)`, circl `ek.EncapsulateTo(ct, ss, m)`), and the nonce, and give the expected `k`, `kem_ct` and `out`.
- **Negative vectors**: a PQ type carrying an Ed25519 key manager, a PQ id missing `k`, a `k` of the wrong length, and a DHIES v2 message addressed to a PQ identity must all be rejected.

## 12. References

[FIPS203] NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard", FIPS 203, August 2024.

[FIPS204] NIST, "Module-Lattice-Based Digital Signature Standard", FIPS 204, August 2024.

[XWING] Barbosa, M., et al., "X-Wing: general-purpose hybrid post-quantum KEM", draft-connolly-cfrg-xwing-kem.

[RFC2104] Krawczyk, H., Bellare, M., and R. Canetti, "HMAC: Keyed-Hashing for Message Authentication", RFC 2104, February 1997.

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

## Appendix A. Proposal: Optional Post-Quantum Sender Authentication

**Status:** proposal for review, not part of this draft unless accepted. A TypeScript prototype exists behind explicit options (A.4); Go and Rust do not implement it.

### A.1. Motivation

DHIES v3 authenticates the sender through `ss = X25519(S_sk, R_pk)` (§9.2). A quantum adversary who recovers `S_sk` from the public `S_pk` can, from then on, produce DHIES v3 messages that the recipient attributes to the sender. Confidentiality is not affected. Some messages need their origin to survive that adversary, for example a signed instruction or a key-rotation notice. For those, and only on request, the sender adds an ML-DSA signature.

### A.2. Format

```
info   = "VAULTYS_DHIES_V3S" || e_pk || S_pk || R_pk || SHA-256(R_ek) || kem_ct
k      = SHA-512(es || ss || kss || info)[0:32]
tbs    = info || nonce || SHA-256(id_S) || SHA-256(id_R) || SHA-256(plaintext)
sig    = Sign_S(SHA-256("VAULTYS_DHIES_V3S" || tbs))
body   = u16be(len(sig)) || sig || plaintext
out    = 0x04 || nonce || e_pk || kem_ct || XSalsa20-Poly1305 secretbox(body, nonce, k)
```

`es`, `ss`, `kss`, `e_pk`, `kem_ct` and `nonce` are computed as in §5.2. `id_S` and `id_R` are the full serialized sender and recipient ids, type byte included. `Sign_S` is the sender's key-manager signature, so `sig` is computed in a dedicated signature domain `VAULTYS_DHIES_V3S`, like `VAULTYS_SIGN`, `VAULTYS_RAW` and `VAULTYS_HANDSHAKE_V1`: a signature obtained through any other API can never be presented as a DHIES signature, and the reverse.

```
+------+------------+------------+----------------+-----------------------------------------------+
| 0x04 | Nonce      | e_pk       | kem_ct         | secretbox(u16be(len(sig)) || sig || plaintext) |
| 1 B  | 24 B       | 32 B       | 1088 B         | 2 + len(sig) + len(plaintext) + 16 B           |
+------+------------+------------+----------------+-----------------------------------------------+
```

| Sender key manager | `len(sig)` | Overhead per message |
|---|---|---|
| Dilithium (ML-DSA-87) | 4627 B | 5790 B |
| Hybrid (Ed25519 + ML-DSA-87) | 4691 B | 5854 B |
| DHIES v3 without signature (§5) | none | 1161 B |

### A.3. Decryption

Given `out`, the recipient's keys, and the expected sender id `id_S`:

1. Reject unless `len(out) >= 1163` and `out[0] == 0x04`; reject unless the recipient is a PQ identity.
2. Recompute `es`, `ss` (rejecting all-zero outputs), `kss` and `k` with the `VAULTYS_DHIES_V3S` label, and open the secretbox.
3. Read `len(sig)`; reject if it is zero or larger than the rest of `body`.
4. Rebuild `tbs` with the decrypted plaintext and verify `sig` with the key manager of `id_S`. Reject unless `id_S` has an ML-DSA signer (Dilithium or Hybrid).

Every failure MUST be reported as the same generic decryption error (§5.3), and the plaintext MUST NOT be released before the signature verifies.

### A.4. Activation

The extension is off unless both sides ask for it:

- **Sender**: an explicit per-message option (TypeScript prototype: `dhiesEncrypt(message, recipientId, { senderSignature: true })`). It requires a PQ recipient and an ML-DSA signer: an Ed25519 or FIDO2 signature would add no post-quantum authentication and is refused.
- **Recipient**: an explicit policy (prototype: `dhiesDecrypt(out, senderId, { senderSignature: "accept" | "require" })`). Without a policy, `0x04` is refused, so the default behaviour of §5 is unchanged. `"accept"` opens both `0x03` and `0x04`; `"require"` opens only `0x04`.

Library versions that do not implement this appendix refuse `0x04` like any unknown version byte.

### A.5. Security Considerations

- **Authentication.** Forging a `0x04` message from `S` requires an ML-DSA-87 signature from `S` (and, for a Hybrid sender, an Ed25519 signature) on top of `ss`. A quantum adversary who recovered `S_sk` can still forge plain `0x03` messages from `S` (§9.2): only a recipient whose policy is `"require"` refuses them. An application that relies on this extension MUST therefore require it for the relevant senders, not merely accept it.
- **No downgrade between 0x03 and 0x04.** The distinct label in `info` gives a different `k`: rewriting the version byte only produces a secretbox failure. Removing the signature from a `0x04` message requires `k`.
- **Deniability is lost.** In DHIES v2 and v3 the recipient can compute any message it could have received (it knows `ss`), so a message proves nothing to a third party. With this extension the recipient holds `tbs` and `sig` and can convince anyone that `S` sent this plaintext to `R`. This is why the extension is opt-in per message.
- **Privacy.** The signature is inside the secretbox: an eavesdropper learns nothing more than with §5, apart from the larger size, which reveals that the sender used the extension.
- **Binding.** `tbs` covers the whole public header (including `nonce`), both full ids and the plaintext digest, so a signature cannot be moved to another message, recipient or sender. `S_pk` and `R_pk` appear both in `info` and through `id_S`, `id_R`; the redundancy is deliberate.
- **Replay** is not addressed, as in §5: a recipient that needs it must track message identifiers at the application level.

### A.6. Open Questions

1. Version byte `0x04` for the signed variant, or a flag field inside the encrypted body of `0x03`?
2. Signature domain as a prefix (`SHA-256("VAULTYS_DHIES_V3S" || tbs)`, consistent with the other VaultysID domains) or as the ML-DSA context string of FIPS 204?
3. Should `"require"` be a per-contact setting stored with the contact rather than a per-call option?
4. Should a future PQ FIDO2 identity (§3.4) be allowed to sign?

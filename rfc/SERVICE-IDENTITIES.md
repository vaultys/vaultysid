# Request for Comments: VaultysID Service Identities

**Status:** Draft, for review. Implemented in the TypeScript reference implementation (`typescript/src/serviceIdentity.ts`, `serviceAnchor.ts`), which generates the test vectors of §7 and §8.5. Go (`go/pkg/serviceid`) and Rust (`rust/src/service_identity.rs`) pass the same vectors; on this branch Go derives Ed25519 and Dilithium identities and Rust Ed25519 ones (hybrid and post-quantum types arrive with the Go and Rust post-quantum identity work).

## 1. Introduction

A VaultysID identity is a single key pair, and its DID (`did:vaultys:…`) is the same everywhere it is used. Two services that both see it can tell that they talk to the same person, even if the person never told either of them who they are. `IdManager` keeps one identity per store, and the only per-service values today are secrets (`requestPRF(appid)`, `hmac("prf|<appid>|prf")`); the identity a service sees in the handshake does not change.

This document defines **service identities**: an application keeps one 32-byte master secret and derives from it, deterministically, a distinct VaultysID identity for each service it connects to. Each service always sees the same identity for the same person, and two services see identities that share no value, so they cannot link them from what they hold.

Existing identities, the handshake and the wire formats are unchanged. A service identity is an ordinary VaultysID identity: it signs, verifies, encrypts, completes handshakes and can be stored like any other.

### 1.1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

`||` is byte concatenation. `lp(s)` is `u32be(len(s)) || s`, with `s` the UTF-8 bytes of a string. `HKDF-SHA-256` is RFC 5869.

## 2. Model

- **Master secret** `M`: 32 bytes from a cryptographically secure random generator, not all zero. The application keeps it like any other secret key (encrypted store, backup). Losing it loses every service identity; anyone who learns it can compute every service identity.
- **Service id**: a string that names a service, in the canonical form of §3. Two spellings of the same service MUST give the same canonical id; two different services MUST give different ones.
- **Service identity**: `deriveServiceIdentity(M, serviceId, options)`, §4.

## 3. Canonical service ids

Implementations MUST decide on an explicit ASCII grammar, and MUST NOT rely on a URL parser alone: the WHATWG parser decodes `%61` to `a`, reads `https://0x7f.1` as `127.0.0.1`, accepts `:0443`, `:/` and `\` as `/`, and converts Unicode hosts to punycode. Ambiguous input is refused, never repaired.

### 3.1. Refused in every form

An input that is not a string, is empty or is longer than 300 characters; any character outside printable ASCII `[\x21-\x7e]` (spaces, controls, Unicode); any of `%`, `\`, `@`, `?`, `#`.

### 3.2. Web origin

`^(https?)://<host>(:<port>)?/?$`, scheme case-insensitive.

- **Host**: lowercased; dot-separated labels of `[a-z0-9-]{1,63}` with no `-` at either end; at least two labels; at most 253 characters. A trailing dot, an empty label and a numeric (or `0x…`) last label are refused.
- **Reserved labels**: a label with `--` in positions 3 and 4 is refused unless it starts with `xn--`. Punycode is accepted but MUST NOT be decoded: `xn--exmple-cva.fr` and `exemple.fr` are two services.
- **Port**: decimal, no leading zero, 1 to 65535. The default port (`:443` for `https`, `:80` for `http`) is removed.
- **Path**: empty or `/`. Query, fragment and userinfo are refused (§3.1).
- **`http` and development hosts**: `http`, `localhost`, `*.localhost` (RFC 6761), canonical dotted-decimal IPv4 literals and IPv6 literals (in the exact form the WHATWG parser serializes, e.g. `[::1]`) are refused unless the caller passes `allowDevelopmentHosts`. An unencrypted origin does not protect the service id.
- **Output**: `<scheme>://<host>[:<port>]`. Implementations SHOULD check that it equals the WHATWG `URL.origin` of the input and refuse otherwise.

### 3.3. Application id

`^app:<reverse-dns>$`, with `<reverse-dns>` following the host rules of §3.2. Upper case is refused, not normalized. The output is the input unchanged.

An `app:` id is only a claim made by the application. A wallet that derives identities for other applications SHOULD take the application identity from the operating system (package name and signing certificate), never from the application itself.

### 3.4. Anything else

Any other form (another scheme, a bare host, a DID, …) is refused.

## 4. Derivation

```
canonical = canonicalServiceId(serviceId, options)
typeName  = role                      (one of "machine", "person", "organization")
          | role || "-pq"             (post-quantum identity type 0x10 | role, rfc/PQ-ENCRYPTION.md §4)
info      = lp("v1") || lp(alg) || lp(typeName) || lp(canonical)
entropy   = HKDF-SHA-256(IKM = M, salt = "vaultysid/service-identity/v1", info, L = 32)
identity  = VaultysId.fromEntropy(entropy, type, alg)
```

- `alg` is the key manager: `ed25519` (default), `dilithium` or `dilithium_ed25519`. A post-quantum type requires a Dilithium or hybrid key manager.
- `type` is the identity type byte: `role` (0, 1 or 2), with the `0x10` flag for a post-quantum identity. The default is a classical person (1).
- The salt is the ASCII string, without a length prefix.
- `entropy` is 32 bytes, the length `generatePerson()` uses: the key managers hash it (`seed = SHA-512(entropy)`) and do not check its length.
- `info` covers the algorithm and the type, so one service never reuses the same entropy for two key managers or two types.
- `fromEntropy` keeps a reference to the buffer it receives. Implementations MUST hand it a copy and erase their own buffer.
- `M` MUST be exactly 32 bytes and not all zero; anything else is refused.

## 5. Using service identities

- An application that connects to service `S` uses the identity derived for `S` in `IdManager` (or `Challenger`), and stores contacts, certificates and metadata **per service identity**. Reusing one store across services links them again through the stored metadata.
- An identity derived for `S` SHOULD only be presented to `S`. Binding the service id into the handshake, so that a certificate made for one service cannot be shown to another, is out of scope here; `rfc/SECURE-CHANNEL.md` describes one way.
- Rotation: there is no built-in rotation. A new master secret changes every service identity at once; to change one, an application can keep its own counter and use a distinct master secret per generation (out of scope here).

## 6. Security considerations

- **Unlinkability.** Service identities are computed by HKDF from a secret. An observer who holds the public ids of two services learns nothing that links them, including an attacker who can compute discrete logarithms: recovering the private key of one service identity gives its seed, and HKDF is one-way, so the master secret and the other identities stay out of reach.
- **The master secret is the single point of failure.** Its compromise exposes every service identity and every relationship. It MUST come from a secure random generator.
- **Do not derive the master secret from a classical identity's X25519 key.** For example, `hmac("prf|…|prf")` on a classical identity is keyed by its X25519 secret, which a quantum attacker recovers from the public field `e`; the attacker would then compute every service identity and link them. For post-quantum identities, the seed-derived PRF key of `rfc/PQ-ENCRYPTION.md` §3.2 does not have this problem.
- **Network and metadata.** IP addresses, timing, device fingerprints and any attribute the person reveals remain linkable outside VaultysID.
- **Same name, different service.** `http` vs `https`, ports and punycode spellings give different identities on purpose (§3.2); a phishing domain gets its own identity, which does not help it impersonate the real service to the person, but the user interface must show the canonical id.

## 7. Test vectors (identities)

Generated by `typescript/test/interops/generate-service-identity-vectors.ts` (`pnpm test:service:vectors`) into `typescript/test/interops/service-identity-vectors.json`:

- `canonical`: input, options, expected output or `"invalid"`;
- `derive`: a public test master secret, services, algorithms and types, with `canonical`, `info`, `entropy`, `did`, the SHA-256 of the serialized `id`, and the full `id` for Ed25519 identities.

The generator recomputes `info` and `entropy` from §4 independently of the implementation and is deterministic.

## 8. Service anchors

A client that connects to `https://example.com` over a peer-to-peer channel (QR code, deep link, relay) has no way to know which identity answers for that origin: anyone can answer and complete a handshake. A **service anchor** is the service's own VaultysID identity, signed by it and published under its origin, so that the client can compare it with the identity that signs the handshake (`expectedPeer`, `rfc/SECURE-CHANNEL.md` §4) before signing COMPLETE.

### 8.1. Format

```
anchor = 0x01 || 0x01 || lp(serviceId) || lp(id) || u16be(len(sig)) || sig
sig    = Sign_identity(lp("vaultysid/service-anchor/v1") || 0x01 || 0x01 || lp(serviceId) || lp(id))     (VAULTYS_RAW)
```

- The first two bytes are the version (`0x01`) and the algorithm (`0x01` = a VaultysID identity and a VaultysID signature by it).
- `serviceId` is canonical (§3) and is a web origin: an `app:` id has no origin to publish under.
- `id` is the identity's serialized public id in version 1, so that one key has one encoding. At most 8 192 bytes.
- `lp` lengths are 4 bytes; the signature length is 2 bytes. Sizes: 175 bytes with an Ed25519 identity, about 7.4 kB with a hybrid one.

### 8.2. Publication

The anchor is served as `application/octet-stream` at `<serviceId>/.well-known/vaultysid-service`, over HTTPS. Its authenticity rests on TLS and the WebPKI certificate of the origin; the signature proves possession of the key and ties the anchor to its origin.

### 8.3. Verification

A client fetching the anchor of origin `S` MUST check, and refuse on any failure:

1. the header, every length, and that the signature ends the anchor exactly (no trailing bytes);
2. that `serviceId` in the anchor **equals** `S` and is canonical: an anchor copied from another origin is refused;
3. that `id` parses and is exactly its own version-1 serialization;
4. the signature of that identity over the signed bytes.

The client then passes the identity as the expected peer of the bound handshake: the handshake fails with `PEER_MISMATCH` if another identity answers.

### 8.4. Pinning

An attacker who controls the origin's web server, or obtains a fraudulent TLS certificate, can replace the anchor. Clients SHOULD pin the DID of the anchor at the first successful connection (trust on first use) and, if a later anchor names another identity, stop and warn the user instead of connecting. Pinning does not protect the very first connection, nor a client that lost its pins (for example after a restore).

### 8.5. Test vectors

`typescript/test/interops/generate-service-anchor-vectors.ts` (`pnpm test:anchor:vectors`) writes `service-anchor-vectors.json`: two fixed Ed25519 anchors (one for a punycode origin) and invalid cases (another origin, header bytes, altered signature, trailing byte, truncation, empty).

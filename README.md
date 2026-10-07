<div align="center">

# VaultysID

**Self-sovereign, post-quantum-ready cryptographic identities — in TypeScript, Go and Rust.**

[![TypeScript](https://github.com/vaultys/vaultysid/actions/workflows/typescript.yml/badge.svg)](https://github.com/vaultys/vaultysid/actions/workflows/typescript.yml)
[![Rust](https://github.com/vaultys/vaultysid/actions/workflows/rust.yml/badge.svg)](https://github.com/vaultys/vaultysid/actions/workflows/rust.yml)
[![npm](https://img.shields.io/npm/v/%40vaultys%2Fid)](https://www.npmjs.com/package/@vaultys/id)
[![NPM Downloads](https://img.shields.io/npm/dw/%40vaultys%2Fid)](https://www.npmjs.com/package/@vaultys/id)
[![Socket](https://socket.dev/api/badge/npm/package/@vaultys/id)](https://socket.dev/npm/package/@vaultys/id)
[![License: MIT](https://img.shields.io/github/license/vaultys/vaultysid)](LICENSE)

</div>

---

VaultysID is a decentralized identity framework. Every identity is a keypair you own — no central authority, no account server. Identities can sign, verify, encrypt to each other, and mutually authenticate through the **handcheck protocol**, a short challenge–response exchange that leaves both parties with a signed certificate of the relationship.

The same wire format is implemented in three languages and continuously tested for byte-for-byte interoperability.

## Highlights

- 🪪 **DIDs out of the box** — every identity resolves to a `did:vaultys:…` identifier and a DID document.
- 🔐 **Modern cryptography** — Ed25519 signatures, X25519 key agreement, DHIES encryption, HMAC/OTP derivation.
- 🛡️ **Post-quantum ready** — Dilithium (ML-DSA-87) and hybrid Ed25519 + Dilithium identities.
- 🔑 **Hardware-backed keys** — FIDO2 / WebAuthn (including PRF) for passkeys and security keys.
- 🤝 **Handcheck protocol** — mutual authentication with nonces, timestamps and signed metadata exchange.
- 📇 **IdManager** — contacts, apps, signed files and metadata on top of a pluggable storage layer.
- 🌐 **Runs everywhere** — Node.js, browsers, native Go binaries and Rust (incl. `cdylib`).

## Implementations

| Language | Path | Package | Status |
|---|---|---|---|
| **TypeScript** (reference) | [`typescript/`](typescript/) | [`@vaultys/id`](https://www.npmjs.com/package/@vaultys/id) | Node.js + browser, FIDO2, PQC |
| **Go** | [`go/`](go/) | `github.com/vaultys/vaultysid/go` | Library + `vaultysid-cli`, PQC |
| **Rust** | [`rust/`](rust/) | `vaultysid` crate | Library, Dilithium, `zeroize`d secrets |

Each folder has its own README with language-specific details.

## Quick start

### TypeScript

```bash
pnpm add @vaultys/id
```

```ts
import { VaultysId, Challenger } from "@vaultys/id";

// Create identities (ed25519 by default, or "dilithium" / "dilithium_ed25519")
const alice = await VaultysId.generatePerson();
const bob = await VaultysId.generateMachine("dilithium_ed25519");

console.log(alice.did); // did:vaultys:…

// Sign & verify
const signature = await alice.signChallenge("hello");
VaultysId.fromId(alice.id).verifyChallenge("hello", signature, false); // true

// Handcheck: mutual authentication
const a = new Challenger(alice);
const b = new Challenger(bob);
a.createChallenge("p2p", "auth", 1);
await b.update(a.getCertificate());
await a.update(b.getCertificate());
await b.update(a.getCertificate());
a.isComplete() && b.isComplete(); // true
```

### Go

```bash
go get github.com/vaultys/vaultysid/go
```

```go
id, _ := vaultysid.GeneratePerson()
fmt.Println(id.DID())

sig, _ := id.Sign([]byte("hello"))
err := id.Verify([]byte("hello"), sig) // nil when valid
```

### Rust

```toml
[dependencies]
vaultysid = { git = "https://github.com/vaultys/vaultysid" }
```

```rust
let id = vaultysid::VaultysId::generate_person().await?;
println!("{}", id.did());
```

### Command line

The Go implementation ships `vaultysid-cli`, a single static binary:

```bash
curl -fsSL https://raw.githubusercontent.com/vaultys/vaultysid/main/scripts/install.sh | bash
```

```bash
vaultysid-cli generate person
```

It covers identity generation, signing/verification of data, challenges and files, DHIES file encryption, and an IdManager store (`manager init | contacts | apps | save-contact …`). Windows users can use [`scripts/install.ps1`](scripts/install.ps1).

## Identity types

| Type | Value | Notes |
|---|---|---|
| Machine | `0` | Software keys, servers and devices |
| Person | `1` | Software keys for individuals |
| Organization | `2` | Software keys for organizations |
| FIDO2 | `3` | Keys held by a security key / passkey |
| FIDO2 PRF | `4` | FIDO2 with the PRF extension for encryption |

Software identities can use `ed25519`, `dilithium` or the hybrid `dilithium_ed25519` algorithm.

## Specifications

The protocols are documented as RFC-style specs in [`rfc/`](rfc/):

- [**DID.md**](rfc/DID.md) — Decentralized Identity Keyring: identity format, key derivation, DID documents.
- [**PROTOCOL.md**](rfc/PROTOCOL.md) — Web of Trust / handcheck protocol: mutual authentication and relationship certificates.
- [**ENCRYPTION.md**](rfc/ENCRYPTION.md) — File encryption format: headers, whole-file and chunked modes.

## Repository layout

```
.
├── typescript/        Reference implementation (@vaultys/id)
├── go/                Go library + vaultysid-cli
├── rust/              Rust crate
├── rfc/               Protocol specifications
├── interops/          Cross-language interoperability test runners
├── kmip-client-go/    KMIP integration tooling
├── scripts/           CLI installers (sh / PowerShell)
└── test/              Repo-level integration tests
```

## Development

**TypeScript** (Node.js 20+, pnpm)

```bash
cd typescript && pnpm install && pnpm build && pnpm test
```

**Go** (Go 1.25+)

```bash
cd go && make build && go test ./...
```

**Rust** (Rust 1.91+)

```bash
cd rust && cargo test
```

**Cross-language interoperability** — verifies that identities, signatures, handchecks and encrypted payloads produced in one language are accepted by the others:

```bash
./interops/run-all-interops.sh
```

### Contributing

New features land in the TypeScript reference implementation first, then in Go and Rust, with interop tests proving the three stay byte-compatible. Please keep backward compatibility with existing identities and update the RFCs when the wire format changes.

## License

[MIT](LICENSE) © Vaultys

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

Monorepo with three implementations of the same identity library, two add-on packages and shared specs:

- `typescript/` — reference implementation, published to npm as `@vaultys/id`. **All pnpm commands must be run from this directory**, not the repo root (there is no root `package.json`).
- `go/` — Go implementation (`github.com/vaultys/vaultysid/go`, library + `vaultysid-cli`), Go 1.25 (`go.mod`). Run `go vet ./...` and `go test ./...` from `go/`.
- `rust/` — native implementation (crate `vaultysid`), must stay byte-compatible with TypeScript. Run all cargo commands from `rust/`. It does not implement all of 4.0 yet (see "Conventions that matter").
- `kmip/` — optional Node.js adapter (`@vaultys/id-kmip`) that delegates Ed25519 signing to a KMIP endpoint.
- `passport-nfc/` — optional desktop and mobile NFC reader for passport identities (type `0x05`).
- `rfc/` — normative specs: `PROTOCOL.md` (Web of Trust / handcheck challenge format), `DID.md`, `ENCRYPTION.md`, `PQ-ENCRYPTION.md` (post-quantum types, PRF key, DHIES v3), `PASSPORT-AA.md`, `SERVICE-IDENTITIES.md`, `SECURE-CHANNEL.md`. Change these first when altering wire formats.
- `interops/` — bash drivers that run TypeScript and Rust processes against each other over a file-based channel.
- `.ai.md` — an older contributor guide; broadly accurate on concepts but stale on file names and on script paths.

## Commands

TypeScript (from `typescript/`):

```bash
pnpm install
pnpm test                                # mocha over test/*.test.ts (tsx via .mocharc.json)
pnpm mocha test/challenger.test.ts       # single test file
pnpm mocha test/challenger.test.ts -g "pattern"   # single test case
pnpm test:web                            # browser bundle + playwright runner (test/runner.ts)
pnpm build                               # build:node (tsc) + build:browser (webpack)
pnpm prettier                            # format src/
```

Rust (from `rust/`):

```bash
cargo test --all-features
cargo test --test typescript_compatibility   # single integration test file
cargo test --doc --all-features
cargo fmt -- --check && cargo clippy --all-targets --all-features -- -D warnings   # CI gates on both
cargo bench
```

Cross-language interop (from repo root):

```bash
interops/run-all-interops.sh                 # full matrix (ed25519 + dilithium, both directions)
interops/run-cross-language-test.sh          # TS accepts / Rust asks
interops/run-cross-language-test.sh reverse
```

Note: the `test:compatibility:rust` and `test:interops` scripts in `typescript/package.json` use paths relative to the repo root (`cd rust`, `test/interops/*.sh`) and do not resolve from `typescript/`. Use the root-level `interops/` scripts and plain `cargo test` instead.

CI (`.github/workflows/`) runs TypeScript tests on Node 20/22/24 and Rust tests on Linux/macOS/Windows, plus fmt, clippy `-D warnings`, tarpaulin coverage, `cargo audit`, `cargo publish --dry-run`, and an MSRV check.

## Architecture

The library layers, bottom up:

1. **KeyManager** (`typescript/src/KeyManager/`, `rust/src/key_manager/`) — one class per crypto scheme behind `AbstractKeyManager`: `Ed25519Manager`, `DilithiumManager` (ML-DSA / post-quantum), `HybridManager` (Ed25519 + Dilithium), `Fido2Manager` and `Fido2PRFManager` (hardware keys via WebAuthn), and `CypherManager` for the encryption half. Each owns serialization of its own key material.

2. **VaultysId** (`VaultysId.ts`, `vaultys_id.rs`) — wraps a KeyManager with a one-byte identity type: Machine 0, Person 1, Organization 2, FIDO2 3, FIDO2PRF 4, Passport AA 5, and the post-quantum types `0x10 | role` (`0x10`–`0x12`, Dilithium or hybrid only, with an ML-KEM key `k`). Roles are computed on `type & 0x0F`. For classical identities `VaultysId.fromId()` dispatches on the exact serialized length (77 = Ed25519, 2638 = Dilithium, 2670 = Hybrid); post-quantum identities are dispatched on the length of `x`, never on the total length (`rfc/PQ-ENCRYPTION.md` §4.2). Any change to key encoding sizes silently breaks parsing — update the length checks and the interop test vectors together. Service identities (`serviceIdentity.ts`) are ordinary identities derived per service from a master secret.

3. **Challenger** (`Challenger.ts`, `rust/src/challenger/`) — the handcheck protocol state machine (`UNINITIALISED → INIT → STEP1 → COMPLETE`, plus `ERROR`), with liveliness windows and metadata exchange. A completed challenge serializes to a *relationship certificate*. TypeScript 4.0 removed the v0 wire format and uses `@msgpack/msgpack` with domain-separated signatures (`VAULTYS_HANDSHAKE_V1`). Rust still has the hand-rolled v0 encoder (`rust/src/challenger/mod.rs`, `encode_v0`) next to v1, and `IdManager.protocol_version` defaults to 1 there; do not "simplify" the Rust v0 path to the library encoder — existing v0 signatures would stop verifying.

4. **Channel** (`MemoryChannel.ts`, `cryptoChannel.ts`, `xwingChannel.ts`) — the `Channel` interface (`send`/`receive`/`close`) that the protocol runs over; `MemoryChannel` for tests, `StreamChannel` bridges to Node/Web streams. `CryptoChannel` encrypts each message with secretbox under ONE symmetric key supplied by the caller, the same in both directions, with no sequence number (no X25519 involved). `xwingChannel.ts` is an X-Wing key exchange with one key per direction and strict sequence numbers, plus a handshake bound to the channel and to the service (`rfc/SECURE-CHANNEL.md`). Interop tests supply a file-based channel implementation.

5. **IdManager** (`IdManager.ts`, `id_manager.rs`) — application layer over a `Store`: contacts, apps, metadata, web-of-trust verification, encrypted backups, and the SRP flows (`startSRP`/`acceptSRP`) that drive `askContact`, `acceptContact`, file sign/encrypt/decrypt, and PRF. Storage is pluggable (`MemoryStorage`, `LocalStorage`, `MessagePackStorage` in `MemoryStorage.ts`).

Platform differences are isolated in `typescript/src/platform/` (`node.ts` vs `browser.ts`, selected by `utils/environment.ts`); everything else must stay environment-agnostic.

## Conventions that matter

- TypeScript imports `Buffer` from the `buffer/` npm shim (not Node's global) so browser and Node builds behave identically. Normalize `Uint8Array` inputs with `Buffer.from()` at API boundaries.
- Anything touching serialization, signatures, or the challenge format is a **cross-implementation contract**: change TypeScript first, regenerate vectors, then update Go and Rust, then run the interop scripts. Deterministic vectors shared with Go and Rust come from `pnpm test:security:vectors` (and `pnpm test:pq:vectors` where the post-quantum vectors are present); `pnpm test:service:vectors`, `pnpm test:anchor:vectors` and `pnpm test:channel:vectors` cover service identities, service anchors and the X-Wing channel, and copy their files to `go/test/compatibility/testdata` and `rust/tests/data` (Go: `pkg/serviceid`, `pkg/xwingchannel`; Rust: `service_identity.rs`, `xwing_channel.rs`). `pnpm test:compatibility:export` creates random identities and is not a deterministic vector source.
- Rust does not implement all of 4.0 (no `VAULTYS_HANDSHAKE_V1` / `VAULTYS_RAW` domains, no DHIES v2, no hybrid identities); `rust/tests/data/security-v2-vectors.json` is not read by any Rust test, and the `interops/` scripts are expected to fail until it does.
- CI: TypeScript, Rust and Go run on pushes to `main` and on pull requests to `main` and `dev`. The Rust MSRV job installs 1.91 while `Cargo.toml` declares `rust-version = "1.90"`.
- `VaultysId.fromEntropy` (TypeScript, Go, Rust) requires exactly 32 bytes; TypeScript copies the buffer so the caller keeps its own.
- `DeprecatedKeyManager` exists in both TypeScript (`src/KeyManager/DeprecatedKeyManager.ts`, exported) and Rust: it is the migration path for old wallets.
- Backward compatibility with v0/v2 identities is tested against the real published package (`@vaultys/id_2` devDependency) in `test/backward_compat/` and `test/v0tov1.test.ts` — keep migration paths in `src/utils/migration.ts` working.
- Post-quantum and WebAuthn key generation are async in both languages; Ed25519-only paths may be sync.
- `typescript/tsconfig.json` is strict and only compiles `index.ts` + `src/**` — tests run through `tsx` and are not part of the build.

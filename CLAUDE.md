# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

Monorepo with two independent implementations of the same identity library plus shared specs:

- `typescript/` — reference implementation, published to npm as `@vaultys/id`. **All pnpm commands must be run from this directory**, not the repo root (there is no root `package.json`).
- `rust/` — native implementation (crate `vaultysid`), must stay byte-compatible with TypeScript. Run all cargo commands from `rust/`.
- `rfc/` — normative specs: `PROTOCOL.md` (Web of Trust / handcheck challenge format), `DID.md`, `ENCRYPTION.md`. Change these first when altering wire formats.
- `interops/` — bash drivers that run TypeScript and Rust processes against each other over a file-based channel.
- `.ai.md` — an older contributor guide; broadly accurate on concepts but stale on file names (e.g. it lists a `DeprecatedKeyManager` that exists only in Rust) and on script paths.

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

2. **VaultysId** (`VaultysId.ts`, `vaultys_id.rs`) — wraps a KeyManager with a one-byte identity type: Machine 0, Person 1, Organization 2, FIDO2 3, FIDO2PRF 4. **`VaultysId.fromId()` dispatches on the exact serialized length** (77 = Ed25519, 2638 = Dilithium, 2670 = Hybrid) after the type byte, so any change to key encoding sizes silently breaks parsing in both languages — update the length checks and the interop test vectors together.

3. **Challenger** (`Challenger.ts`, `rust/src/challenger/`) — the handcheck protocol state machine (`UNINITIALISED → INIT → STEP1 → COMPLETE`, plus `ERROR`), with liveliness windows and metadata exchange. A completed challenge serializes to a *relationship certificate*. Two wire versions coexist: **v0 uses a hand-rolled MessagePack encoder** (`encode_v0`, `writeString`/`writeBuffer`/`writeInt`) that emits fields in a fixed order to keep signatures byte-stable, while v1 uses `@msgpack/msgpack`. Do not "simplify" the v0 path to use the library encoder — existing signatures would stop verifying. `IdManager.protocol_version` still defaults to 0.

4. **Channel** (`MemoryChannel.ts`, `cryptoChannel.ts`) — the `Channel` interface (`send`/`receive`/`close`) that the protocol runs over; `MemoryChannel` for tests, `CryptoChannel` adds X25519 end-to-end encryption, `StreamChannel` bridges to Node/Web streams. Interop tests supply a file-based channel implementation.

5. **IdManager** (`IdManager.ts`, `id_manager.rs`) — application layer over a `Store`: contacts, apps, metadata, web-of-trust verification, encrypted backups, and the SRP flows (`startSRP`/`acceptSRP`) that drive `askContact`, `acceptContact`, file sign/encrypt/decrypt, and PRF. Storage is pluggable (`MemoryStorage`, `LocalStorage`, `MessagePackStorage` in `MemoryStorage.ts`).

Platform differences are isolated in `typescript/src/platform/` (`node.ts` vs `browser.ts`, selected by `utils/environment.ts`); everything else must stay environment-agnostic.

## Conventions that matter

- TypeScript imports `Buffer` from the `buffer/` npm shim (not Node's global) so browser and Node builds behave identically. Normalize `Uint8Array` inputs with `Buffer.from()` at API boundaries.
- Anything touching serialization, signatures, or the challenge format is a **cross-implementation contract**: change TypeScript first, regenerate vectors via `pnpm test:compatibility:export`, then update Rust, then run the interop scripts. `typescript/test/vectors.test.ts`, `test/backward_compat/`, and `rust/tests/typescript_compatibility.rs` are the guardrails.
- Backward compatibility with v0/v2 identities is tested against the real published package (`@vaultys/id_2` devDependency) in `test/backward_compat/` and `test/v0tov1.test.ts` — keep migration paths in `src/utils/migration.ts` working.
- Post-quantum and WebAuthn key generation are async in both languages; Ed25519-only paths may be sync.
- `typescript/tsconfig.json` is strict and only compiles `index.ts` + `src/**` — tests run through `tsx` and are not part of the build.

# Vaultys ID
This is the main library to handle Vaultys DID and handcheck protocol

[![test](https://github.com/vaultys/vaultysid/actions/workflows/test.yml/badge.svg)](https://github.com/vaultys/vaultysid/actions/workflows/test.yml)
[![Socket](https://socket.dev/api/badge/npm/package/@vaultys/id)](https://socket.dev/npm/package/@vaultys/id)
![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/npm/%40vaultys%2Fid)
![NPM Downloads](https://img.shields.io/npm/dw/%40vaultys%2Fid)
![GitHub License](https://img.shields.io/github/license/vaultys/vaultysid)
![Dependents (via libraries.io)](https://img.shields.io/librariesio/dependents/npm/%40vaultys%2Fid)



## Breaking security changes (4.0.0)

4.0.0 is an intentionally breaking security release. Identity ids, DIDs and secrets are unchanged, but the
protocols below are not compatible with 3.x and older:

- **Handshake (Challenger)**: only challenge `version = 1` exists; v0 encoding and v0 signatures are removed and any
  other version is rejected. Signatures are `sign(SHA-256("VAULTYS_HANDSHAKE_V1" || unsignedBytes))` through the
  handshake-only `signHandshake` / `verifyHandshake`. Strict state machine: a responder only accepts an INIT, an
  initiator only a STEP1 matching exactly what it sent, a responder only a COMPLETE matching exactly its STEP1
  (no more signing a STEP1 it never initiated, no replayed COMPLETE, no reflection). `setChallenge` /
  `fromCertificate` are read-only. `createChallenge(protocol, service, metadata?)` lost its `version` argument and
  `IdManager.protocol_version` / `setProtocolVersion` are gone. Accept callbacks receive the remote identity and
  accept flows require an INIT as first message.
- **Signature domains**: `signChallenge` keeps `VAULTYS_SIGN`; the new public `VaultysId.sign` / `verify` use
  `VAULTYS_RAW`. No public API can produce a handshake signature anymore.
- **DHIES v2** replaces DHIES: sender-authenticated (`es || ss`), `0x02 || nonce || e_pk || secretbox`; old
  ciphertexts can't be decrypted.
- **IdManager persistence**: the store always keeps the full secret (`store.secret`); stores/backups restore the
  exact same identity (algorithm, type, DID). Entropy-only (legacy) stores are rejected; restore them explicitly
  with `new IdManager(await VaultysId.fromEntropy(entropy, type, alg), store)`. Empty backup passphrases are rejected.
- **Default deny** for remote services: `acceptPRF`, `acceptDecryptFile`/`acceptEncryptFile`, `acceptDecrypt` and
  `acceptSignFile` refuse unless an `accept` callback approves the remote. The file-encryption PRF namespace
  (`encryption/...`) is never served through `acceptPRF` to another identity.
- **WebAuthn**: no silent fallback to the insecure `SoftCredentials` authenticator; call `enableSoftCredentials()`
  explicitly (tests only). Assertions require `type === "webauthn.get"` and the UP flag, and check rpId/origin when
  configured with `configureWebAuthn({ rpId, origin })`. FIDO2 Dilithium5 keys are parsed correctly.
- **OTP**: `await me.getOTP(contact, prefix?, timelock?, time?)` is now
  `HMAC-SHA256(SHA-256(X25519(my cypher sk, contact cypher pk)), prefix || certificate || uint64be(counter))`, so only
  the two parties can compute it.
- **requestConnect / acceptConnect** are now a plain `p2p`/`auth` handshake (optionally pinned to a DID) saving the
  contact.
- Untrusted ids, secrets and certificates are length-checked and never throw uncaught `TypeError`s;
  `VaultysId.decrypt` correctly parses a hex sender id.

Cross-language vectors: `test/interops/security-v2-vectors.json` (`npx tsx test/interops/generate-security-v2-vectors.ts`).

## Getting Started
- install nodejs (20.x recommended) and pnpm (https://pnpm.io/fr/installation)
- checkout this repo
- install dependencies: `pnpm i`
- compile for web `pnpm build_web` or for node `pnpm build`
- run test `pnpm test`

## Checkout examples
The repository also have some examples. Try them:
- `pnpx tsx example/sideChannelAttack.js`
- `pnpx tsx example/logChallenge.js`

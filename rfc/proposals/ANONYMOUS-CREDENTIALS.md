# Proposal: VaultysID Anonymous Credentials (BBS)

**Status:** Proposal for discussion. **Nothing in this document is implemented in this repository.** It records the design, the formats and the security findings of a working prototype built on top of VaultysID 4.0, so that an implementation can start from them. Every open decision is listed in §12.

## 1. Goal

Let a person prove an attribute about themselves — "over 18", "nationality FR" — to a service, without revealing who they are and without letting the issuer or several services link the presentations.

- An **issuer** checks a document once (for example an identity card read over NFC) and issues a credential.
- The **holder** keeps the credential in their wallet and later presents a **selective-disclosure proof** of some attributes to a **verifier** (a service).
- Two presentations of the same credential are unlinkable, to verifiers and to the issuer. The issuer never sees the holder's secret.

VaultysID today authenticates identities; it has no notion of attributes. This proposal adds attributes on top of the existing pieces: service identities (`rfc/SERVICE-IDENTITIES.md`), the X-Wing channel and bound handshake (`rfc/SECURE-CHANNEL.md`), and the identity of the issuer as a VaultysID.

## 2. Non-goals

- **Identification.** A credential says "the holder of this wallet was issued `over18=true` by issuer I". It does not prove that the person presenting it is the document's owner (see §10.7).
- **Post-quantum unlinkability.** BBS is pairing-based. §10.4 explains what a quantum attacker can and cannot do.
- **Compatibility with the EU Digital Identity Wallet formats** (mdoc, SD-JWT VC). Those are correlatable by design (the same signature is shown each time) and are a different track.

## 3. Building blocks and library status

| Block | Specification | Status (November 2026) |
|---|---|---|
| BBS signatures, BLS12-381-SHA-256 | draft-irtf-cfrg-bbs-signatures | Mature draft; `@digitalbazaar/bbs-signatures` 3.1.0 passes the published vectors |
| Blind BBS (holder-committed messages) | draft-irtf-cfrg-bbs-blind-signatures | -05 current; the library implements -01 to -03 (15/15 vectors of those revisions), not -05 |
| BBS per-verifier pseudonyms | draft-irtf-cfrg-bbs-pseudonyms | -05 current; the library implements -01 (13/13 vectors), whose Security Considerations section is empty ("TODO") |
| Pairings, hash-to-curve | — | `@noble/curves` BLS12-381, JavaScript, not constant-time |

Two blockers for production:

1. **The blind and pseudonym modules of `@digitalbazaar/bbs-signatures` are not exported.** The prototype opened them with a `pnpm patch` that only changes the `exports` field (`./internal/blind`, `./internal/pseudonym`, `./internal/ciphersuites`). That is acceptable for a prototype, not for a library. The first step is to ask the maintainers to export them, or to wait for an implementation of the current (-05) drafts.
2. **Another BBS library, `@docknetwork/crypto-wasm-ts` 0.67.0, does not enforce witness equality** when verifying composite proofs: a proof made with two different secrets verifies, so one holder's credential can be presented under another holder's pseudonym. Any library chosen MUST pass the witness-equality tests of §11 before anything else is written.

Recommendation: implement **Blind BBS without pseudonyms first** (§5 mode `standard`), behind the agility byte of §4.1, and add pseudonyms only with an implementation of pseudonyms -02 or later (§10.4).

## 4. Conventions

### 4.1. Format agility

Every serialized object starts with `version || algorithm` (`|| mode` for credentials). `algorithm 0x01` = BBS-BLS12-381-SHA-256 with the blind and pseudonym constructions of the revisions the library implements. An implementation of the -05 drafts changes the proof encoding and MUST take a new version. `algorithm 0x02` is reserved for a future post-quantum scheme.

### 4.2. Labels

Every derivation and signature uses a versioned label. Proposed values (to be confirmed by the maintainers):

| Use | Label |
|---|---|
| Holder secret (HKDF salt) | `vaultysid/holder-secret/v1` |
| BBS header | `vaultysid/cred/v2` |
| Presentation header | `vaultysid/cred-presentation/v2` |
| Issuer key certificate (VaultysID signature) | `vaultysid/issuer-key/v1` |
| Issuer key id | `vaultysid/cred-key-id/v1` |
| Pseudonym context | `vaultysid/cred-pseudonym/v1` |
| Issuer key log (VaultysID signature) | `vaultysid/issuer-key-log/v1` |

`lp(x)` is `u32be(len(x)) || x`.

## 5. Credential content

Messages, in a fixed order, each `name=value` in UTF-8 (the library maps them to scalars):

| Index | Message | Disclosed |
|---|---|---|
| 0 | `schema=vaultysid-cred/v1` | always |
| 1 | `type=<credential type>`, e.g. `type=age-nationality` | always |
| 2 | `exp=YYYY-MM-DD`, the epoch (§7) | always |
| 3 | `over18=true` or `over18=false` | if requested |
| 4 | `nationality=FR` (ISO 3166-1 alpha-2) | if requested |
| 5 | `birth_year=YYYY`, or empty if unknown | only if explicitly requested; an empty value cannot be disclosed |
| 6 | `level=<how the issuer checked>` | hidden by default |
| committed | `secret_prover_blind`, then the holder secret (blind message) [, `nym_secret` in pseudonym mode] | never |

Two modes, chosen at issuance and bound in the BBS header:

| Mode | Byte | Construction |
|---|---|---|
| standard (default) | `0x00` | Blind BBS, no pseudonym. The holder secret is a blind message ("key binding", blind draft §Security Considerations). Proven with `BlindProofGen` / `BlindProofVerify`. |
| pseudonym (explicit request only) | `0x01` | Blind BBS with pseudonym: `nym_secret = prover_nym + signer_nym_entropy`, `pseudonym = hash_to_curve_g1(context_id) · nym_secret`. `prover_nym` is fresh random (64 uniform bytes reduced mod r) **per credential**, kept in the stored credential, never sent. |

## 6. Derivations

```
holderSecret = I2OSP(OS2IP(HKDF-SHA-256(IKM = master (32 bytes, non-zero), salt = "vaultysid/holder-secret/v1",
                                        info = lp("v1") || lp("BLS12-381-SHA-256"), L = 64)) mod r, 32)    (refuse 0)
keyId        = SHA-256(lp("vaultysid/cred-key-id/v1") || lp(epoch) || pk_bbs)
header       = lp("vaultysid/cred/v2") || u8(mode) || keyId
ph           = lp("vaultysid/cred-presentation/v2") || lp(canonical serviceId) || lp(nonce, 32)
               || lp(th, 32) || lp(holder DID for this service)
context_id   = lp("vaultysid/cred-pseudonym/v1") || lp(canonical serviceId)                    (pseudonym mode)
```

- `master` is the same master secret as service identities (`rfc/SERVICE-IDENTITIES.md` §2); the holder secret is a separate HKDF output.
- `th` is the transcript hash of the X-Wing channel the presentation travels in (`rfc/SECURE-CHANNEL.md` §3.1) and the holder DID is the service identity authenticated by the bound handshake. The verifier recomputes `ph` from **its own** channel and handshake. This closes the relay attack of §10.1.

## 7. Epochs and issuer keys

- `epoch(now)` = the date (UTC) of the Sunday that ends the ISO week containing `now + 7 days`. A credential is valid 8 to 14 days, and every credential issued in the same week carries the same `exp`: the anonymity set is everyone issued that week (§10.6).
- **One BBS key per issuer and per epoch**, published in advance in an **append-only public key log** signed by the issuer's VaultysID identity:

```
IssuerKeyLog = 0x01 || 0x01 || u16be(n) || n × (lp(epoch) || pk (96)) || u16be(len) || sig
sig          = issuer.sign(lp("vaultysid/issuer-key-log/v1") || 0x01 || 0x01 || u16be(n) || n × (lp(epoch) || pk))
```

  1 ≤ n ≤ 4096, epochs strictly increasing. A new version MUST repeat every entry of the previous one. Wallets keep the latest version seen and refuse a log that does not extend it; at issuance they accept only the key for `epoch(now)`; at presentation, only the key for the credential's epoch. Verifiers trust only keys in the log, and refuse two keys for one epoch.
- Validity at verification: `date(now) ≤ exp ≤ epoch(now)`.

Why: without it, a dishonest issuer can give each holder their own key (or a rare epoch) and recognise them by the disclosed `keyId` (§10.2).

## 8. Formats

| Format | Content | Size |
|---|---|---|
| `IssuerKeyLog` | §7 | 6 + 110·n + sig |
| `IssuanceRequest` | `02 01 || mode || commitment_with_proof` | 147 (standard) / 179 (pseudonym) |
| `IssuedCredential` | `02 01 || mode || keyId (32) || signature (80) || [signer_nym_entropy (32)] || u8(7) || lp(m_0) … lp(m_6)` | 267 / 299 |
| `Credential` (wallet) | `02 01 || mode || pk (96) || signature (80) || secret_prover_blind (32) || [signer_nym_entropy (32) || prover_nym (32)] || u8(7) || lp(m_i)…` | 363 / 427 |
| `Presentation` | `02 01 || mode || keyId || u8(R) || R × u8(index) || R × lp(m_index) || [pseudonym (48)] || lp(proof)` | 534–574 / 614–654 |

- The proof length is fixed and MUST be checked before calling the library: `272 + 32 · (7 − R + 2)` (standard), `272 + 32 · (7 − R + 3)` (pseudonym). Otherwise the library infers the number of committed messages from it.
- Indexes are strictly increasing and include 0, 1 and 2.
- `Credential` does not contain the holder secret: a copied credential alone is useless.
- Scalars are refused if zero or ≥ r; a pseudonym must be a valid G1 point other than the identity.

## 9. Protocols

All exchanges run inside an X-Wing channel after a bound handshake. The holder uses its **service identity** for the issuer and for each verifier.

### 9.1. Issuance

1. Holder ↔ issuer: channel, bound handshake (the holder checks the issuer's anchor, `rfc/SERVICE-IDENTITIES.md` §8).
2. The holder fetches the issuer key log, checks it extends the last version seen, and takes the key for `epoch(now)`.
3. The issuer checks the document (out of scope here; see §10.7) and erases what it read.
4. Holder → issuer: `IssuanceRequest` (commitment to `secret_prover_blind` and the holder secret, with its proof).
5. Issuer → holder: `IssuedCredential`. The holder verifies it with the key and stores a `Credential`.

### 9.2. Presentation

1. Holder ↔ verifier: channel, bound handshake, anchor check.
2. Verifier → holder: `AttributeRequest { nonce (32, single use), required: [attributes], pseudonym: bool }`.
3. Holder → verifier: `Presentation` disclosing indexes 0, 1, 2 and **exactly** the required attributes, with `ph` of §6.
4. The verifier checks, in this order: format → service id, nonce, `th`, holder DID → messages 0–2 and names → key (known, epoch = `exp`, unique for the epoch) → mode → disclosed attributes equal to `required` → expiry → BBS proof (with pseudonym if requested). It never throws on untrusted input and returns a typed reason.

### 9.3. Proposed API (TypeScript)

```ts
export const CREDENTIAL_ATTRIBUTES: readonly ["over18", "nationality", "birth_year", "level"];
export function credentialEpoch(now: Date): string;
// issuer
export function generateIssuerKeys(epoch: string): Promise<IssuerKeys>;
export function appendIssuerKeyLog(issuer: VaultysId, previous: Uint8Array | null, key: IssuerPublicKey): Promise<Uint8Array>;
export function issue(keys: IssuerKeys, request: Uint8Array, attributes: CredentialAttributes, now: Date): Promise<Uint8Array>;
// holder
export function deriveHolderSecret(master: Uint8Array): Uint8Array;
export function createIssuanceRequest(holderSecret: Uint8Array, options?: { pseudonym?: boolean }): Promise<{ request: Uint8Array; state: IssuanceState }>;
export function finalizeCredential(state: IssuanceState, holderSecret: Uint8Array, issued: Uint8Array, key: IssuerPublicKey): Promise<Uint8Array>;
export function prove(credential: Uint8Array, holderSecret: Uint8Array, disclose: readonly CredentialAttribute[],
  context: { serviceId: string; nonce: Uint8Array; sessionHash: Uint8Array; holderDid: string }, options?: { pseudonym?: boolean }): Promise<Uint8Array>;
// verifier
export function verifyIssuerKeyLog(log: Uint8Array, issuer: VaultysId, previous?: Uint8Array | null): readonly IssuerPublicKey[] | null;
export function verifyPresentation(presentation: Uint8Array, options: VerifyOptions): Promise<VerifyResult>;
```

No function takes a randomness parameter; vector generators use internal functions that the package does not export.

## 10. Security considerations (findings of the prototype review)

1. **Relay of a presentation (critical if ignored).** A presentation bound only to a nonce can be relayed: a fake service forwards the real service's nonce and gets someone else's credential validated. Binding `th` and the holder DID into `ph` (§6) fixes it.
2. **Issuer key tagging.** One key (or a rare epoch) per holder lets the issuer recognise holders through the disclosed `keyId`, with or without pseudonyms. Fixed by the public append-only log, one key per epoch (§7). Residual assumption: everyone reads the same log; witnesses or a transparency log are needed for that.
3. **Pseudonyms are opt-in.** By default no pseudonym is produced. When one is, verifiers should not keep it beyond the epoch; that is unverifiable and belongs in their privacy policy. A pseudonym gives no anti-Sybil property as long as the issuer issues several credentials per document.
4. **Quantum attacker.** Plain BBS presentations stay unlinkable even against an attacker who computes discrete logarithms ("everlasting unlinkability"). Pseudonyms do not: with pseudonyms -01 (one secret), such an attacker recovers `nym_secret` from one pseudonym and links every service. Pseudonyms -02 and later use N secrets and keep up to N−1 contexts unlinkable. Do not build pseudonyms on -01.
5. **Issuer that keeps `signer_nym_entropy`.** With a `prover_nym` constant across credentials, two pseudonyms of one account satisfy `ψ1 − ψ2 = OP·(e1 − e2)`, which an issuer that kept the `e` values can test. A fresh `prover_nym` per credential (§5) removes it.
6. **Anonymity set** = everyone issued in the same week by the same issuer; small issuers or quiet weeks give small sets. Timing and network metadata remain.
7. **Holder ≠ document owner.** Reading a card proves possession of the card (the CAN is printed on it), not that the person is its owner. Issuers must say what they checked (`level`), and verifiers must not treat a credential as identification.
8. **Witness equality.** Test it explicitly with every library and every version (§11), before writing protocol code.
9. **Side channels.** The JavaScript pairing and BBS code is not constant-time; secrets held as `bigint` cannot be reliably erased.

## 11. Test plan

Written before the protocol code:

- **Witness equality** (first): B's pseudonym pasted on A's proof; a proof of A's signature with B's `nym_secret`; pseudonyms swapped between two valid presentations; B's `prover_nym` with A's entropy; A's proof sent to B's context. All MUST be refused.
- Published CFRG vectors for the revisions implemented, and the current revisions' vectors recorded as "observed" so that a library update shows.
- A full deterministic chain: master → holder secret → request → issuance → credential → presentations to two services.
- Relay of a presentation to another session (refused), tagging issuer (two holders of one epoch present the same `keyId`), a log that does not extend the previous one (refused), expired and future epochs, disclosure of more or fewer attributes than required, malformed proofs of every length.

## 12. Open decisions

1. Which library: wait for exported blind/pseudonym modules, or a -05 implementation (and its audit).
2. Attribute vocabulary and credential types (shared registry or per issuer).
3. Who runs issuers, and how their VaultysID identities and logs are discovered (anchors under their origin, a list signed by a third party, …).
4. Whether pseudonyms are offered at all before an N-secret implementation exists.
5. Issuance limits per document and per epoch (anti-Sybil) versus not recognising the document (unlinkability to the issuer).
6. Revocation: short epochs only (as proposed), or a privacy-preserving status mechanism.
7. Transparency of the issuer key log (witnesses, gossip between wallets).

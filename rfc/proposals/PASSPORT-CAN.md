# Proposal: Card Access Number (CAN) for `passport-nfc`

**Status:** Proposal. Not implemented. It describes what `passport-nfc` and `@vaultys/passport-nfc` need to open identity cards with the CAN, what that changes for passport identities (type `0x05`, `rfc/PASSPORT-AA.md`), and how to test it.

## 1. Context

`passport-nfc` opens the chip with PACE or BAC using a password derived from the **MRZ** only (`internal/chip/chip.go`, `password.NewPasswordMrz`). Identity cards are usually opened with the **Card Access Number**: six digits printed on the front. It is shorter to type, and it avoids sending the MRZ data (document number, dates of birth and expiry) to the helper.

Observed on one French electronic identity card (CNIe):

- PACE with the CAN works (`id-PACE-ECDH-GM-AES-CBC-CMAC-256`, brainpoolP256r1, about 0.5 s);
- EF.COM and the SOD advertise DG1, DG2, DG3, DG11, DG12, DG13 and DG14, **neither DG7 nor DG15**;
- Chip Authentication (`id-CA-ECDH-AES-CBC-CMAC-256`, key in DG14) is present and verifies.

So the CAN is the natural way in, but this particular card **cannot** back a type `0x05` identity, which needs an Active Authentication key in DG15. CAN support is still useful: other cards and passports that have DG15 can be opened with it, and the CAN path is a prerequisite for any later use of identity cards (for example as evidence for an issuer, `rfc/proposals/ANONYMOUS-CREDENTIALS.md`).

## 2. Library support

`gmrtd` v1.9.1, already a dependency, provides `password.NewPasswordCan(can string)` (`PASSWORD_TYPE_CAN`, key `k = CAN`). No new dependency is needed, and no PACE code is written by hand.

## 3. Changes

### 3.1. Helper request (`main.go`)

Add one field and make the two passwords exclusive:

```go
type request struct {
	Operation      string   `json:"operation"`
	Reader         string   `json:"reader,omitempty"`
	MRZ            string   `json:"mrz,omitempty"`
	CAN            string   `json:"can,omitempty"` // new: exactly 6 ASCII digits
	Challenges     [][]byte `json:"challenges,omitempty"`
	ResponseLength int      `json:"responseLength,omitempty"`
}
```

- Exactly one of `mrz` and `can` MUST be present for `read` and `sign`; both or neither is a request error.
- `can` MUST match `^[0-9]{6}$`. Anything else is refused before touching the chip.
- The CAN goes over standard input like the MRZ, never on the command line or in the environment, and is never logged or echoed in errors.

### 3.2. Chip access (`internal/chip/chip.go`)

```go
// PasswordCAN returns the PACE password of a Card Access Number (six digits).
func PasswordCAN(can string) (*password.Password, error) {
	if len(can) != 6 || strings.Trim(can, "0123456789") != "" {
		return nil, errors.New("invalid card access number; enter the 6 digits printed on the card")
	}
	return password.NewPasswordCan(can), nil
}
```

- With a CAN, only **PACE** is possible (BAC has no CAN mode). If the chip does not advertise PACE in EF.CardAccess, fail with "this document does not support access by card number; use the MRZ".
- When DG15 is missing, replace "passport has no DG15 Active Authentication key" with "this document has no Active Authentication key (DG15); some identity cards have none, and it cannot be used for a passport identity". Keep a stable error code so the adapter can map it.

### 3.3. Mobile API (`mobile/passport.go`)

Add CAN entry points next to the MRZ ones, so that existing callers keep working:

```go
func ReadPassportCAN(can string, link Transceiver) (*DataGroups, error)
func SignPassportCAN(can string, link Transceiver, challenges [][]byte, responseLength int) ([][]byte, error)
```

The iOS and Android wrappers (`mobile/ios`, `mobile/android`) expose the same two calls. Apps SHOULD offer the CAN first for identity cards and the MRZ for passports.

### 3.4. Node.js adapter (`index.js`, `index.d.ts`)

```ts
export type PassportAccess = { mrz: string; can?: never } | { can: string; mrz?: never };
export interface PassportNfcOptions extends PassportNfcHelperOptions {
  /** The printed MRZ (passports) or the 6-digit Card Access Number (identity cards). Exactly one. */
  access: PassportAccess;
  readerName?: string;
}
```

To stay compatible, keep accepting a top-level `mrz` for one release and map it to `access: { mrz }`.

### 3.5. Documentation

- `passport-nfc/README.md`: how to find the CAN, that it is a possession factor and not a secret, and the DG15 requirement.
- `rfc/PASSPORT-AA.md` §Scope already notes that some identity cards lack DG15.

## 4. Privacy and security

- **The CAN is not a secret.** It is printed on the card: anyone holding the card can open it. Reading a chip with the CAN proves possession of the card, never that the person is its owner.
- Do not store the CAN. Erase it from memory once PACE is done (Go strings cannot be erased; keep it as a `[]byte` internally where possible and zero it).
- Read only the data groups needed: DG14 and DG15 for type `0x05`. Never read DG2, DG3 or DG7 (photo, fingerprints, signature image).
- Report only structure in errors and logs, never data group contents, full hashes of data groups or the SOD signature: those are stable identifiers for ten years.
- Rate-limit attempts: chips may block or slow down after repeated failed PACE attempts.

## 5. Tests

- Request validation: CAN with 5 or 7 digits, letters, spaces, both MRZ and CAN, neither (all refused before any APDU).
- Mock chip (`internal/chip/chip_test.go`): PACE with CAN succeeds against a simulated chip; a chip without PACE gives the "use the MRZ" error; a chip without DG15 gives the new error message and code.
- Node.js adapter: `access: { can }` reaches the helper on standard input only; the legacy `mrz` option still works.
- Manual test on hardware: one passport with DG15 (MRZ and, where supported, CAN), one identity card without DG15 (expected refusal with the new message).

## 6. Out of scope

- Identity cards without Active Authentication as VaultysID identities. Chip Authentication cannot be used for that: it authenticates the chip implicitly through session keys and produces no signature a third party can verify.
- Passive authentication against national CSCA lists, and any claim about the document holder's identity.

# Passport Active Authentication identities (draft)

VaultysID type `0x05` uses the Active Authentication key in an eMRTD chip.
[ICAO Doc 9303 Part 11, §6.1](https://www.icao.int/publications/documents/9303_p11_cons_en.pdf)
defines the chip operation. The composition below is specific to VaultysID.

## Public identity

The type byte `05` precedes a MessagePack map in field order `{v, x, e, h}`.
The version `v` is 1. The binary field `x` contains the DER SubjectPublicKeyInfo
from DG15 and `e` contains the 32-byte local X25519 public key. The integer
`h` is 0 for RSA (the AA message recovery trailer identifies the hash), and
1 through 4 for ECDSA SHA-224, SHA-256, SHA-384 and SHA-512 respectively, as
specified by the chip's DG14 ActiveAuthenticationInfo. The DID is derived
from the resulting public identity as in [DID.md](DID.md).

## Scope

Type `0x05` requires a document whose chip has an Active Authentication key in
DG15. Many passports have one; some European identity cards do not. One French
electronic identity card (CNIe) read over NFC, for example, gave PACE access
with the CAN, advertised DG1, DG2, DG3, DG11, DG12, DG13 and DG14 but neither
DG7 nor DG15, and supported Chip Authentication (key in DG14). No type `0x05`
identity can be created for such a card. Chip Authentication cannot replace
Active Authentication here: it is an implicit authentication by key agreement
and produces no signature that a third party can verify.

The `passport-nfc` helper derives the PACE password from the MRZ only; access
with the CAN, the usual way to open an identity card, is not offered.

The reader operates on an already selected passport application and handles
access control and secure messaging where required. No MRZ, document number,
reader configuration or civil identity evidence appears in the public ID.
X25519 key agreement uses an application-managed secret.

## VaultysID signature

Let `D` be the existing 32-byte VaultysID domain digest for a raw message,
application challenge, or v1 handcheck transcript. Let `ID` be the full
serialized public identity. Generate a fresh 32-byte salt `R` per signature.

Compute `SHA-256(ASCII("VAULTYS_PASSPORT_AA_V1") || SHA-256(ID) || D || R)`.
In order, split its 32 bytes into four eight-byte challenges. If any repeat,
choose a new salt. Send one INTERNAL AUTHENTICATE command per challenge.
The VaultysID signature is `R || S0 || S1 || S2 || S3`, where each `Si` is
the raw, fixed-width chip response. Verification requires four distinct
challenges, exact length, and a valid response for each in order.

ECDSA responses encode fixed-width `r || s`. RSA responses use ISO/IEC
9796-2 scheme 1 with partial recovery. The verifier checks the `6A`
header, the ICAO trailer for the selected digest, and the hash of the
recovered chip nonce followed by the requested challenge.

A single eight-byte chip challenge would truncate the transcript binding.
The four responses bind the entire digest even though the chip accepts
eight bytes at a time. Interactive authentication uses a fresh verifier
nonce in the signed transcript. A valid response demonstrates access
to the registered AA key. Passport authenticity and holder identity
depend on separate evidence, such as Passive Authentication of DG15 and
issuer validation. The chip operation also provides no user-verification
or transaction-display signal.

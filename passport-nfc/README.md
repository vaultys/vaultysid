# Passport NFC reader

`@vaultys/passport-nfc` connects VaultysID Passport Active Authentication to a
USB contactless reader through the operating system's PC/SC interface. The
native helper uses [gmrtd](https://github.com/gmrtd/gmrtd) for passport access
and secure messaging and [scard](https://github.com/ebfe/scard) for PC/SC.
The Node.js adapter is installed separately from `@vaultys/id`.

For phone-based NFC, see the [iOS and Android libraries](mobile/README.md).

## Install from this checkout

You need Node.js 20 or later, Go 1.26.10 or later, a C compiler for cgo, and an
ISO 14443 contactless reader with a PC/SC driver. macOS provides the PC/SC
framework. On Linux, install PC/SC Lite with its development headers and a
driver for your reader, then start its smart-card service.

From the repository root, build the helper and pack both npm packages.

```sh
(cd passport-nfc && mkdir -p bin && CGO_ENABLED=1 go build -o bin/vaultys-passport-nfc . && npm pack)
(cd typescript && pnpm install --frozen-lockfile && pnpm build && pnpm pack)
```

Install the two tarballs in your Node.js application.

```sh
npm install /path/to/vaultys-id-4.0.0.tgz /path/to/vaultys-passport-nfc-0.1.0.tgz
```

## Read and sign

Place the passport's chip on the reader. Pass the printed machine-readable
zone as `mrz`. The helper uses the MRZ for PACE or BAC and reads DG15 and
DG14. When more than one PC/SC reader is present, choose the exact name
returned by `listPassportReaders()`.

```ts
import { VaultysId } from "@vaultys/id";
import { listPassportReaders, readPassportAA } from "@vaultys/passport-nfc";

const executable = "/absolute/path/to/vaultys-passport-nfc";
const readers = await listPassportReaders({ executable });
console.log(readers);

const passport = await readPassportAA({ executable, mrz, readerName });
const identity = VaultysId.fromPassportAA({ ...passport, encryptionSecretKey });
const signature = await identity.sign(message);
const valid = VaultysId.fromId(identity.id).verify(message, signature);
```

Keep the passport on the reader while signing. The adapter opens a fresh chip
session for each signature and sends all four AA challenges before closing it.
The `encryptionSecretKey` is your stable 32-byte local X25519 secret. Keep it
in your app's secret store to recreate the same identity.

The MRZ is sent to the local helper over standard input. The helper returns
the data groups or AA responses required by `@vaultys/id`. A passport must
advertise an AA key in DG15. The supported signing keys and passport evidence
scope are described in the [VaultysID passport section](../typescript/README.md#passport-active-authentication).

## Tests

Run `go test ./...` from `passport-nfc/` for request validation, application
selection, and mock chip operations. Run `pnpm build:node` from
`typescript/`, then run `npm test` from `passport-nfc/` for the Node.js
adapter test with a simulated reader and VaultysID signature verification.

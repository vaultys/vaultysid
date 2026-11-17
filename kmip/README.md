# @vaultys/id-kmip

This optional package runs on Node.js 20 or later and works with
`VaultysId.fromSigner()` in `@vaultys/id`. It has no runtime npm dependencies.
It requires a KMIP 2.1 endpoint that supports the
`Sign` operation with PureEd25519. Provision an active Ed25519 private key
with signing permission and obtain its KMIP key ID and raw 32-byte public key.
The endpoint must accept the input in `Data` and return a raw 64-byte Ed25519
signature. VaultysID prepares the domain-separated input before delegating
signing.

## Install from this checkout

Build and pack both packages from the repository root.

```sh
(cd typescript && pnpm install --frozen-lockfile && pnpm build && pnpm pack)
(cd kmip && pnpm install --frozen-lockfile && pnpm pack)
```

In your Node.js app, install the resulting archives using the paths from the
pack commands.

```sh
pnpm add /path/to/vaultys-id-4.0.0.tgz /path/to/vaultys-id-kmip-0.1.0.tgz
```

## Sign with a provisioned key

Supply your client certificate and private key as PEM values. Set `ca` to the
server's CA certificate if you use a private CA. The default port is 5696.

```typescript
import { VaultysId } from "@vaultys/id";
import { KMIPSigner } from "@vaultys/id-kmip";

const signer = new KMIPSigner({
  host: "hsm.example.com",
  keyId: signingKeyId,
  publicKey: signingPublicKey,
  cert: clientCertificatePem,
  key: clientPrivateKeyPem,
  ca: serverCaPem,
});

const identity = await VaultysId.fromSigner(signer, encryptionSecretKey);
const signature = await identity.sign(message);
const valid = VaultysId.fromId(identity.id).verify(message, signature);
```

`encryptionSecretKey` is a separate 32-byte X25519 secret. For a new identity,
generate it once with a secure random generator and keep it in your secret
store. To restore the same identity, supply the same signing public key and
X25519 secret. An existing Ed25519 identity keeps its ID only when both public
keys and the serialization version match. Use `.toVersion(0)` if restoring a
version 0 public identity.

You can use another signing backend by implementing `Ed25519Signer`. The
private signing key stays with the backend. `getSecret()` and the
`IdManager` profile/backup flow require an exportable signing secret. For an
externally backed identity, restore it explicitly with `VaultysId.fromSigner`.

## Development

Install the dependencies in both `typescript/` and `kmip/`. From `kmip/`,
run `pnpm test` for the mutual-TLS mock integration tests, which require
OpenSSL for test certificates. The mock checks the KMIP wire requests and
VaultysID verification. To validate your hardware, run the example against
your KMIP endpoint with its provisioned key and confirm that `valid` is true.

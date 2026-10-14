# VaultysID CLI

A command-line interface for VaultysID - decentralized identity management for machines, persons, and organizations.

## Installation

### From Source

```bash
git clone https://github.com/vaultys/vaultysid.git
cd vaultysid/go

make build-cli     # build ./vaultysid-cli
make install-cli   # or install into GOPATH/bin
```

### Pre-built Binaries

Download pre-built binaries from the [releases page](https://github.com/vaultys/vaultysid/releases).

## Handling secrets

Secrets are **never** accepted as command-line arguments (argv is visible to
other local users through `ps` and is saved in shell history). Every command
that needs your identity secret reads it from, in order:

1. `--secret-file PATH` - a file containing the hex or base64 secret. The CLI
   warns if the file is readable by group or others; keep it at mode `0600`.
2. `--secret-file -` - the secret is read from stdin.
3. `VAULTYSID_SECRET` - environment variable.

Newly created secrets (`generate`, `from-entropy`) are written to the file
given with `--out` (created with mode `0600`, never overwritten without
`--force`); only public information is printed.

Backups are always encrypted with a non-empty password, read from
`--password-file PATH`, `VAULTYSID_PASSWORD`, or an interactive prompt
(no echo) when stdin is a terminal.

## Usage

### Identities

```bash
# Generate an identity (machine, person or organization)
vaultysid-cli generate person --out me.secret
vaultysid-cli generate machine --alg dilithium --out machine.secret

# Derive an identity from 32 bytes of entropy (hex/base64)
vaultysid-cli from-entropy person --entropy-file entropy.hex --out me.secret
cat entropy.hex | vaultysid-cli from-entropy person --entropy-file - --out me.secret

# Show the public identity of a secret
vaultysid-cli from-secret --secret-file me.secret

# Public (read-only) identity from an id
vaultysid-cli from-id <public-id>

# Information / DID about a public id, or about your own identity
vaultysid-cli info <public-id>
vaultysid-cli info --secret-file me.secret
vaultysid-cli did <public-id>
vaultysid-cli did --secret-file me.secret
```

### Signing and verification

```bash
# Sign data: the signature covers SHA-256("VAULTYS_RAW" || data)
vaultysid-cli sign data <hex-data> --secret-file me.secret
vaultysid-cli verify data <public-id> <hex-data> <signature>

# Sign an application challenge: SHA-256("VAULTYS_SIGN" || challenge)
vaultysid-cli sign challenge <hex-challenge> --secret-file me.secret
vaultysid-cli verify challenge <public-id> <hex-challenge> <signature>

# Sign a file; verification needs the signed challenge printed by `sign file`
vaultysid-cli sign file document.txt --secret-file me.secret
vaultysid-cli verify file <public-id> document.txt <signature> --challenge <challenge>
```

Signatures produced by these commands are domain separated and can never be
used as handshake signatures (which use `VAULTYS_HANDSHAKE_V1`).

### Encryption

Files are encrypted for yourself, keyed by your identity (rfc/ENCRYPTION.md).

```bash
# Writes document.txt.encrypted; the input is left untouched
vaultysid-cli encrypt document.txt --secret-file me.secret
vaultysid-cli encrypt document.txt --out doc.enc --secret-file me.secret
vaultysid-cli encrypt document.txt --in-place --secret-file me.secret

# Writes document.txt (mode 0600); refuses to overwrite unless --force
vaultysid-cli decrypt document.txt.encrypted --secret-file me.secret
vaultysid-cli decrypt doc.enc --out document.txt --secret-file me.secret
```

### HMAC

```bash
vaultysid-cli hmac <input> --secret-file me.secret
```

### IDManager

The store file contains your secret and is always written with mode `0600`.

```bash
export VAULTYSID_SECRET="$(cat me.secret)"   # or pass --secret-file to each command

vaultysid-cli manager init me.store
vaultysid-cli manager set-name me.store "John Doe"
vaultysid-cli manager set-email me.store "john@example.com"
vaultysid-cli manager set-phone me.store "+1-555-0123"

vaultysid-cli manager save-contact me.store <contact-id> name="Alice Smith" email="alice@example.com"
vaultysid-cli manager contacts me.store

vaultysid-cli manager save-app me.store app.example.com <server-id>
vaultysid-cli manager apps me.store

# Password-encrypted backup (prompted, or --password-file / VAULTYSID_PASSWORD)
vaultysid-cli manager export me.store --out backup.b64
vaultysid-cli manager import restored.store @backup.b64
```

## Global Flags

- `-o, --output`: Output format (`json` or `text`, default: `json`)
- `-e, --encoding`: Output encoding (`hex` or `base64`, default: `hex`)
- `-v, --verbose`: Verbose output
- `--secret-file`: Identity secret file (`-` for stdin)
- `--password-file`: Backup password file

## Testing

```bash
make test-cli
go test -v ./cmd/vaultysid-cli/...
```

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

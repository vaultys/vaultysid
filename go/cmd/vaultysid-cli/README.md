# VaultysID CLI

A command-line interface for VaultysID - decentralized identity management for machines, persons, and organizations.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/vaultys/vaultysid.git
cd vaultysid/go

# Build the CLI
make build-cli

# Or install directly to your GOPATH/bin
make install-cli
```

### Pre-built Binaries

Download pre-built binaries from the [releases page](https://github.com/vaultys/vaultysid/releases).

## Usage

### Basic Commands

#### Generate a New Identity

```bash
# Generate a machine identity
vaultysid-cli generate machine

# Generate a person identity
vaultysid-cli generate person

# Generate an organization identity
vaultysid-cli generate organization
```

#### Create Identity from Entropy

```bash
# From hex-encoded entropy (32 bytes)
vaultysid-cli from-entropy machine <hex-entropy> -e hex

# From base64-encoded entropy
vaultysid-cli from-entropy person <base64-entropy> -e base64
```

#### Create Identity from Existing Secret

```bash
vaultysid-cli from-secret <base64-secret>
```

#### Create Identity from Public ID (Read-only)

```bash
vaultysid-cli from-id <public-id>
```

### Signing Operations

#### Sign Data

```bash
# Sign arbitrary data
vaultysid-cli sign data <secret> <base64-data>

# Sign a challenge with protocol prefix
vaultysid-cli sign challenge <secret> <base64-challenge>

# Sign a file
vaultysid-cli sign file <secret> <file-path>
```

### Verification Operations

#### Verify Signatures

```bash
# Verify data signature
vaultysid-cli verify data <public-id> <base64-data> <base64-signature>

# Verify challenge signature
vaultysid-cli verify challenge <public-id> <base64-challenge> <base64-signature>

# Verify file signature
vaultysid-cli verify file <public-id> <file-path> <base64-signature>
```

### Encryption/Decryption

#### Encrypt Files

```bash
vaultysid-cli encrypt <secret> <input-file> <output-file>
```

#### Decrypt Files

```bash
vaultysid-cli decrypt <secret> <input-file> <output-file>
```

### Identity Information

#### Show Identity Info

```bash
# From secret
vaultysid-cli info <secret>

# From public ID
vaultysid-cli info <public-id>
```

#### Get DID (Decentralized Identifier)

```bash
vaultysid-cli did <secret-or-id>
```

#### Compute HMAC

```bash
vaultysid-cli hmac <secret> <base64-data>
```

### IDManager Operations

The IDManager provides persistent storage and management of identities, contacts, and applications.

#### Initialize Manager

```bash
vaultysid-cli manager init <secret> <store-file>
```

#### Set User Information

```bash
# Set name
vaultysid-cli manager set-name <secret> <store-file> "John Doe"

# Set email
vaultysid-cli manager set-email <secret> <store-file> "john@example.com"

# Set phone
vaultysid-cli manager set-phone <secret> <store-file> "+1-555-0123"
```

#### Manage Contacts

```bash
# Save a contact
vaultysid-cli manager save-contact <secret> <store-file> <contact-id> \
    name="Alice Smith" email="alice@example.com" phone="+1-555-0456"

# List all contacts
vaultysid-cli manager contacts <secret> <store-file>
```

#### Manage Applications

```bash
# Save an application
vaultysid-cli manager save-app <secret> <store-file> <site> <server-id> \
    description="My App" version="1.0.0"

# List all applications
vaultysid-cli manager apps <secret> <store-file>
```

#### Export/Import Data

```bash
# Export manager data
vaultysid-cli manager export <secret> <store-file> > backup.data

# Import manager data
vaultysid-cli manager import <secret> <store-file> <base64-data>
```

## Global Flags

- `-o, --output`: Output format (`text` or `json`, default: `text`)
- `-e, --encoding`: Input/output encoding (`base64` or `hex`, default: `base64`)
- `-v, --verbose`: Enable verbose output

## Examples

### Complete Workflow Example

```bash
# 1. Generate a new identity
vaultysid-cli generate person -o json > identity.json

# 2. Extract secret and ID
SECRET=$(cat identity.json | jq -r .secret)
ID=$(cat identity.json | jq -r .id)

# 3. Initialize IDManager
vaultysid-cli manager init $SECRET myidentity.store

# 4. Set personal information
vaultysid-cli manager set-name $SECRET myidentity.store "John Doe"
vaultysid-cli manager set-email $SECRET myidentity.store "john@example.com"

# 5. Sign a document
echo "Important document" > document.txt
SIGNATURE=$(vaultysid-cli sign file $SECRET document.txt -o json | jq -r .signature)

# 6. Verify the signature (anyone can do this with your public ID)
vaultysid-cli verify file $ID document.txt $SIGNATURE

# 7. Encrypt a sensitive file
vaultysid-cli encrypt $SECRET sensitive.txt sensitive.enc

# 8. Decrypt the file
vaultysid-cli decrypt $SECRET sensitive.enc decrypted.txt
```

### Contact Management Example

```bash
# Generate identities for contacts
CONTACT1_ID=$(vaultysid-cli generate person -o json | jq -r .id)
CONTACT2_ID=$(vaultysid-cli generate organization -o json | jq -r .id)

# Save contacts
vaultysid-cli manager save-contact $SECRET myidentity.store $CONTACT1_ID \
    name="Alice Smith" email="alice@example.com"

vaultysid-cli manager save-contact $SECRET myidentity.store $CONTACT2_ID \
    name="ACME Corp" type="organization" website="https://acme.com"

# List all contacts
vaultysid-cli manager contacts $SECRET myidentity.store -o json
```

### Backup and Restore Example

```bash
# Export all data
vaultysid-cli manager export $SECRET myidentity.store > backup.b64

# Create new store and import
vaultysid-cli manager init $SECRET restored.store
vaultysid-cli manager import $SECRET restored.store $(cat backup.b64)

# Verify restoration
vaultysid-cli manager contacts $SECRET restored.store
```

## Security Considerations

1. **Secret Storage**: Never store secrets in plain text. Use secure key management systems or encrypted storage.

2. **File Permissions**: Ensure store files have appropriate permissions (e.g., `chmod 600 myidentity.store`).

3. **Backup**: Regularly backup your store files and keep backups secure.

4. **Transport**: When transmitting secrets or sensitive data, use secure channels (HTTPS, SSH, etc.).

## Testing

Run the test suite:

```bash
# Run all CLI tests
make test-cli

# Run with verbose output
go test -v ./cmd/vaultysid-cli/...

# Run integration tests
go test -tags integration ./cmd/vaultysid-cli/...

# Run benchmarks
go test -bench=. ./cmd/vaultysid-cli/...
```

## Troubleshooting

### Common Issues

1. **"Invalid secret" error**: Ensure the secret is properly base64-encoded and is exactly 32 bytes when decoded.

2. **"Store file not found" error**: Make sure the store file path is correct and the file exists.

3. **"Invalid ID format" error**: VaultysID public IDs should be in the format `vid:type:base58string`.

4. **Encoding issues**: Use the `-e` flag to specify the correct encoding (base64 or hex).

### Debug Mode

Enable verbose output for debugging:

```bash
vaultysid-cli -v <command> <args>
```

## Contributing

Please see the main [CONTRIBUTING.md](../../CONTRIBUTING.md) file for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.
# VaultysID Go Implementation

A Go implementation of the VaultysID decentralized identity framework, interoperable with the TypeScript reference implementation.

## Features

- 🔐 **Cryptography**: Ed25519/X25519 for classical signing and key exchange, ML-DSA-87 (FIPS 204, formerly Dilithium5) for post-quantum signing
- 🔄 **Cross-Implementation Compatibility**: msgpack wire format matches the TypeScript implementation byte-for-byte
- 📦 **Single Binary**: `vaultysid-cli` deploys with no runtime dependencies
- 🛡️ **Memory Handling**: Secret material is zeroed on `CleanSecureData`/`SecureErase`

## Installation

### Using Go Modules

```bash
go get github.com/vaultys/vaultysid/go
```

### Building from Source

```bash
git clone https://github.com/vaultys/vaultysid
cd vaultysid/go
make build
```

## Quick Start

### Generate an Identity

```go
package main

import (
    "fmt"
    "log"

    "github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

func main() {
    // Generate a new person identity
    id, err := vaultysid.GeneratePerson()
    if err != nil {
        log.Fatal(err)
    }

    // Get the DID (Decentralized Identifier)
    fmt.Printf("DID: %s\n", id.DID())

    // Get the identity bytes for sharing
    idBytes := id.ToBytes()
    fmt.Printf("Identity: %x\n", idBytes)
}
```

### Sign and Verify Data

```go
// Sign some data
data := []byte("Hello, VaultysID!")
signature, err := id.Sign(data)
if err != nil {
    log.Fatal(err)
}

// Verify the signature (can be done by anyone with the public identity;
// certificate may be nil if none was issued)
publicID, err := vaultysid.FromID(id.ToBytes(), nil)
if err != nil {
    log.Fatal(err)
}
err = publicID.Verify(data, signature)
fmt.Printf("Signature valid: %v\n", err == nil)
```

### Handcheck Protocol (Challenge-Response)

```go
package main

import (
    "github.com/vaultys/vaultysid/go/pkg/challenger"
    "github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

func main() {
    // Create two identities
    alice, _ := vaultysid.GeneratePerson()
    bob, _ := vaultysid.GeneratePerson()

    // Initialize challengers
    aliceChallenger := challenger.New(alice)
    bobChallenger := challenger.New(bob)

    // Alice initiates
    aliceInit, _ := aliceChallenger.Init("protocol", "service")

    // Bob responds with step1
    bobStep1, _ := bobChallenger.Step1(aliceInit)

    // Alice completes with step2
    aliceStep2, _ := aliceChallenger.Step2(bobStep1)

    // Bob finalizes and both parties are authenticated
    bobChallenger.Finalize(aliceStep2)
}
```

### Post-Quantum Cryptography

```go
import "github.com/vaultys/vaultysid/go/pkg/vaultysid"

// Generate a post-quantum (ML-DSA-87) identity
pqID, err := vaultysid.GeneratePersonAlg("dilithium")
if err != nil {
    log.Fatal(err)
}
```

Combined classical + post-quantum ("dilithium_ed25519") identities are not yet implemented; requesting that algorithm returns an error.

## API Reference

### Core Types

#### VaultysID
The main identity container that pairs an identity type with a key manager.

```go
type VaultysID struct {
    Type        IdentityType
    KeyManager  keymanager.KeyManager
    Certificate []byte
}

// Identity types
const (
    TypeMachine      IdentityType = 0
    TypePerson       IdentityType = 1
    TypeOrganization IdentityType = 2
    TypeFIDO2        IdentityType = 3  // verification only, see Limitations
    TypeFIDO2PRF     IdentityType = 4  // verification only, see Limitations
)
```

`Certificate` is an opaque byte string carried alongside the identity; it is not an X.509 certificate and nothing in this package parses or validates it as one.

#### Key Managers
- `Ed25519Manager`: Ed25519 signing, X25519 Diffie-Hellman (default, recommended)
- `DilithiumManager`: ML-DSA-87 post-quantum signing paired with an X25519 encryption key
- `FIDO2Manager`: WebAuthn/FIDO2 signature verification (no signing, see Limitations)

### Main Functions

```go
// Identity generation
func GenerateMachine() (*VaultysID, error)
func GeneratePerson() (*VaultysID, error)
func GenerateOrganization() (*VaultysID, error)
func GeneratePersonAlg(alg string) (*VaultysID, error) // alg: "ed25519" or "dilithium"

// Import/Export
func FromID(id []byte, certificate []byte) (*VaultysID, error)
func (v *VaultysID) ToBytes() []byte
func (v *VaultysID) DID() string

// Cryptographic operations
func (v *VaultysID) Sign(data []byte) ([]byte, error)
func (v *VaultysID) Verify(data, signature []byte) error
func (v *VaultysID) DiffieHellman(peerPublicKey []byte) ([]byte, error)
```

`Verify` returns `nil` on a valid signature and a non-nil `error` otherwise; it does not return a `bool`.

## Development

### Prerequisites

- Go 1.21 or later
- Make (for build automation)
- golangci-lint (for linting)

### Setup Development Environment

```bash
make setup  # Install development tools
make mod    # Download dependencies
```

### Building

```bash
make build           # Build for current platform
make build-all       # Build for all platforms
make build-minimal   # Build without post-quantum crypto
```

### Testing

```bash
make test            # Run unit tests
make test-coverage   # Generate coverage report
make test-compatibility  # Test TypeScript compatibility
make bench           # Run benchmarks
make fuzz           # Run fuzz tests
```

### Code Quality

```bash
make fmt    # Format code
make lint   # Run linters
make vet    # Run go vet
make check  # Run all checks
```

## Compatibility

### TypeScript Interoperability

The Go implementation's wire format (msgpack encoding of identities, challenges, and signed payloads) matches the TypeScript reference implementation:

```go
// Load identity created by TypeScript
tsIdentityBytes, _ := os.ReadFile("identity.bin")
id, err := vaultysid.FromID(tsIdentityBytes, nil)

// Signatures are cross-compatible
signature := tsGeneratedSignature
err = id.Verify(data, signature)  // err == nil on a valid signature
```

### Test Vectors

Compatibility is checked against vectors shared with the TypeScript implementation, under `go/test/compatibility/`:

```bash
make test-compatibility
```

## Architecture

```
pkg/
├── vaultysid/      # Core identity type, DID, challenge signing, DHIES
├── keymanager/     # Ed25519Manager, DilithiumManager, FIDO2Manager, DHIES
├── challenger/     # Handcheck (challenge-response) protocol
├── crypto/         # Hashing, HMAC, secretbox/scrypt encryption primitives
├── idmanager/      # Contact/app storage, key derivation, file signing and encryption
└── utils/          # Hex/base64/UTF-8 conversions
```

## Security Considerations

- **Key Storage**: Private keys are kept in memory only, never persisted unless explicitly exported via `GetSecret`
- **Secure Random**: Uses `crypto/rand` for all random number generation
- **Memory Clearing**: `CleanSecureData`/`SecureErase` zero sensitive buffers after use

## Limitations

### FIDO2/WebAuthn
- `FIDO2Manager` verifies FIDO2/WebAuthn signatures produced elsewhere; it cannot itself sign, since that requires a hardware authenticator and a browser WebAuthn ceremony
- No direct hardware key access

For creating FIDO2 signatures, use the TypeScript implementation in a browser environment.

### Not yet implemented
- Hybrid classical + post-quantum identities (`dilithium_ed25519`)
- `VaultysID.Encrypt`, `Decrypt`, `Signcrypt`, `GetOTP`, `GetOTPHMAC` are present as stubs and return errors

## Contributing

Please see [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for design notes and remaining work.

### Running Tests Before Submitting

```bash
make check  # Format, lint, and test
make test-compatibility  # Ensure TypeScript compatibility
```

## Examples

```bash
go run go/examples/fido2_vaultysid_example.go
```

## Troubleshooting

### Binary Size Issues

If the binary is too large due to post-quantum crypto:

```bash
# Build minimal version without PQC
make build-minimal
```

### Performance Profiling

```bash
# Generate CPU profile
go test -cpuprofile=cpu.prof -bench=.
go tool pprof cpu.prof

# Generate memory profile
go test -memprofile=mem.prof -bench=.
go tool pprof mem.prof
```

### Debugging

```bash
# Use delve debugger
dlv debug cmd/vaultysid-cli/main.go
```

## License

MIT License - See [LICENSE](../../LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/vaultys/vaultysid/issues)
- **Documentation**: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)
- **TypeScript Reference**: [../typescript/README.md](../typescript/README.md)
- **Rust Implementation**: [../rust/README.md](../rust/README.md)

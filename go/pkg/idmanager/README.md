# IdManager Package

The `idmanager` package provides high-level identity management functionality for VaultysID, including contact management, application management, file operations, and key derivation.

## Overview

IdManager is the main interface for managing VaultysID identities and their relationships. It provides:

- **Identity Management**: Store and manage your own identity with metadata (name, email, phone)
- **Contact Management**: Store and manage other VaultysID identities as contacts
- **Application Management**: Track applications/services that interact with your identity
- **File Operations**: Sign, verify, encrypt, and decrypt files
- **Key Derivation**: Derive protocol-specific and service-specific keys
- **Backup/Restore**: Export and import encrypted backups of your identity data
- **Protocol Support**: Support for both v0 and v1 protocols

## Installation

```bash
go get github.com/vaultys/vaultysid/go/pkg/idmanager
```

## Usage

### Creating an IdManager

```go
import (
    "github.com/vaultys/vaultysid/go/pkg/idmanager"
    "github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// Generate a new identity
id, err := vaultysid.GeneratePerson()
if err != nil {
    panic(err)
}

// Create a memory store
store := idmanager.NewMemoryStore()

// Create the manager
manager := idmanager.NewManager(id, store)
```

`NewManager` always persists the identity's secret (`getEntropy` is currently a stub that always returns `nil`), so restoring from raw entropy rather than from the persisted secret is not yet supported through this path.

### Setting Identity Properties

```go
// Set identity metadata
manager.SetName("Alice Smith")
manager.SetEmail("alice@example.com")
manager.SetPhone("+1234567890")

// Get identity information
name := manager.Name()
email := manager.Email()
displayName := manager.DisplayName() // Returns name or truncated DID
```

### Managing Contacts

```go
// Create a contact
contactID, _ := vaultysid.GeneratePerson()

// Save contact with metadata
metadata := map[string]interface{}{
    "name": "Bob Jones",
    "email": "bob@example.com",
}
err := manager.SaveContact(contactID, metadata)

// Retrieve contact
contact, err := manager.GetContact(contactID.DID())

// Set additional metadata
manager.SetContactMetadata(contactID.DID(), "nickname", "Bobby")

// List all contacts
contacts := manager.Contacts()
for _, c := range contacts {
    fmt.Printf("Contact: %x\n", c.ID) // c.ID is the raw VaultysID bytes; OldDID is unset for contacts saved this way
}
```

### Managing Applications

`SaveApp` accepts either a machine `*vaultysid.VaultysID` or a legacy `(site string, serverIDHex string)` pair, and dispatches on the type of its first argument:

```go
// VaultysID form: registers the app under its own DID, optionally under a
// custom display name (second argument)
appID, _ := vaultysid.GenerateMachine()
err := manager.SaveApp(appID, "app.example.com")

// Legacy form: site name plus a hex-encoded server ID
err = manager.SaveApp("app.example.com", "736572766572")

// Retrieve application
app, err := manager.GetApp("app.example.com")

// List all applications
apps := manager.Apps()
```

### File Operations

#### Signing Files

```go
file := &idmanager.File{
    Name:        "document.pdf",
    Type:        "application/pdf",
    ArrayBuffer: fileData,
}

// Sign the file
signature, err := manager.SignFile(file)

// Verify a file signature; contactID is the signer's public VaultysID and
// userVerification enables the FIDO2 user-verification flag when the
// contact's KeyManager is FIDO2-backed
err = manager.VerifyFile(file, signature, contactID, false)
```

#### Encrypting Files

`EncryptFile`/`DecryptFile` take no password: the encryption key is an HMAC derived from the manager's own identity, not from user-supplied material.

```go
// Encrypt a file
encryptedFile, err := manager.EncryptFile(file)

// Decrypt the file
decryptedFile, err := manager.DecryptFile(encryptedFile)
```

### Key Derivation

`derivation.go` implements HKDF-based protocol keys, service keys, encryption/signing/session keys, and channel key derivation as `Manager` methods — but every one of them (`deriveProtocolKey`, `deriveServiceKey`, `deriveKey`, `deriveEncryptionKey`, `deriveSigningKey`, `deriveSessionKey`, `deriveChannelKeys`, `storeDerivedKey`, `getStoredDerivedKey`, `cleanupExpiredKeys`) is unexported. They are not part of this package's public API and cannot be called from outside `idmanager`. Exporting them, if needed, is unstarted work.

### PRF (Pseudo-Random Function)

```go
// Generate PRF for an application
appID := "app.example.com"
salt := []byte("random-salt")
prf, err := manager.PRF(appID, salt)
```

### Challenge/Response Protocol

```go
// Sign a challenge
challenge := []byte("challenge-data")
signature, err := manager.SignChallenge(challenge)

// Verify a challenge
err = manager.VerifyChallenge(challenge, signature)

// Set protocol version (0 or 1)
manager.SetProtocolVersion(1)
```

### Backup and Restore

```go
// Export encrypted backup
password := "backup-password"
backup, err := manager.ExportBackup(password)

// Import backup
restoredManager, err := idmanager.ImportBackup(backup, password)
```

### Storage Options

#### Memory Storage

```go
// Simple in-memory storage
store := idmanager.NewMemoryStore()

// Memory storage with custom save function
store := idmanager.NewMemoryStoreWithSave(func() error {
    // Custom save logic
    return nil
})
```

#### File Storage

```go
// File-based persistent storage
store, err := idmanager.NewFileStore("/path/to/storage.json")
```

#### Storage Interface

The `Store` interface allows custom storage implementations:

```go
type Store interface {
    // Basic operations
    Set(key string, value interface{})
    Get(key string) interface{}
    Delete(key string)
    List() []string

    // Substore management
    Substore(key string) Store
    ListSubstores() []string
    DeleteSubstore(key string)
    RenameSubstore(oldname, newname string)

    // Persistence
    Save() error
    Destroy() error

    // Serialization
    ToString() (string, error)
    ToJSON() (interface{}, error)
    FromString(data string) error
    FromJSON(data interface{}) error
}
```

## Protocol Versions

The IdManager supports two protocol versions:

- **Protocol v0**: Legacy protocol for backward compatibility
- **Protocol v1**: Current protocol with improved security

Set the protocol version based on your compatibility requirements:

```go
// NewManager defaults to v0; call this to opt in to v1
manager.SetProtocolVersion(1)

// Explicit v0 for backward compatibility
manager.SetProtocolVersion(0)
```

## Security Considerations

1. **Password Security**: Use strong passwords for file encryption and backups
2. **Key Storage**: Derived keys are stored in memory/disk - ensure proper access controls
3. **Expired Keys**: Regularly clean up expired session keys
4. **Protocol Version**: Use v1 protocol unless v0 compatibility is required
5. **Backup Storage**: Store encrypted backups securely

## Thread Safety

The IdManager is thread-safe and uses internal locking for concurrent access. Multiple goroutines can safely use the same manager instance.

## Examples

See the `examples/` directory for complete working examples:

- Basic identity management
- Contact synchronization
- File encryption/signing
- Key derivation patterns
- Backup and restore

## Testing

Run the test suite:

```bash
go test ./pkg/idmanager
```

Run with coverage:

```bash
go test ./pkg/idmanager -cover
```

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. New features include tests
3. Documentation is updated
4. Code follows Go conventions

## License

See the LICENSE file in the root repository.
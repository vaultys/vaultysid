package idmanager

import (
	"github.com/vaultys/vaultysid-go/pkg/vaultysid"
)

// ProtocolVersion represents the protocol version (0 or 1)
type ProtocolVersion int

const (
	ProtocolV0 ProtocolVersion = 0
	ProtocolV1 ProtocolVersion = 1
)

// IdentityManager defines the interface for identity management
type IdentityManager interface {
	// Core identity operations
	SetProtocolVersion(version int) error
	ExportBackup(password string) (string, error)

	// Contact management
	Contacts() []StoredContact
	GetContact(did string) (*vaultysid.VaultysID, error)
	SaveContact(contact *vaultysid.VaultysID, metadata map[string]interface{}) error
	SetContactMetadata(did string, key string, value interface{}) error
	GetContactMetadata(did string, key string) (interface{}, error)

	// App management
	Apps() []StoredApp
	GetApp(site string) (*StoredApp, error)
	SaveApp(site string, serverID []byte, certificate []byte) error

	// Identity properties
	SetName(name string) error
	Name() string
	DisplayName() string
	SetPhone(phone string) error
	Phone() string
	SetEmail(email string) error
	Email() string

	// Cryptographic operations
	SignChallenge(challenge []byte) ([]byte, error)
	VerifyChallenge(challenge []byte, signature []byte) error
	SignFile(file *File) (*FileSignature, error)
	VerifyFile(file *File, signature *FileSignature) error
	EncryptFile(file *File) (*File, error)
	DecryptFile(encryptedFile *File) (*File, error)
	PRF(appID string, salt []byte) ([]byte, error)

	// Hardware identity
	IsHardware() bool
}

// ChallengeResult represents the result of a challenge operation
type ChallengeResult struct {
	Challenge []byte                 `msgpack:"challenge"`
	Response  []byte                 `msgpack:"response,omitempty"`
	Metadata  map[string]interface{} `msgpack:"metadata,omitempty"`
	Success   bool                   `msgpack:"success"`
}

// ConnectionRequest represents a connection request between identities
type ConnectionRequest struct {
	FromDID     string `msgpack:"from_did"`
	ToDID       string `msgpack:"to_did"`
	Challenge   []byte `msgpack:"challenge"`
	DHPublicKey []byte `msgpack:"dh_public_key"`
	Timestamp   int64  `msgpack:"timestamp"`
}

// ConnectionResponse represents a connection response
type ConnectionResponse struct {
	FromDID     string `msgpack:"from_did"`
	ToDID       string `msgpack:"to_did"`
	Response    []byte `msgpack:"response"`
	DHPublicKey []byte `msgpack:"dh_public_key"`
	Accepted    bool   `msgpack:"accepted"`
	Timestamp   int64  `msgpack:"timestamp"`
}

// EncryptionRequest represents a request to encrypt data
type EncryptionRequest struct {
	Data      []byte `msgpack:"data"`
	Recipient string `msgpack:"recipient"`
}

// DecryptionRequest represents a request to decrypt data
type DecryptionRequest struct {
	EncryptedData []byte `msgpack:"encrypted_data"`
	Sender        string `msgpack:"sender"`
}

// SignatureRequest represents a request to sign data
type SignatureRequest struct {
	Data      []byte `msgpack:"data"`
	Algorithm string `msgpack:"algorithm"`
}

// VerificationRequest represents a request to verify a signature
type VerificationRequest struct {
	Data      []byte `msgpack:"data"`
	Signature []byte `msgpack:"signature"`
	Signer    string `msgpack:"signer"`
}

// WebOfTrustCertificate represents a certificate in the web of trust
type WebOfTrustCertificate struct {
	Issuer      []byte                 `msgpack:"issuer"`
	Subject     []byte                 `msgpack:"subject"`
	Certificate []byte                 `msgpack:"certificate"`
	Signature   []byte                 `msgpack:"signature"`
	IssuedAt    int64                  `msgpack:"issued_at"`
	ExpiresAt   int64                  `msgpack:"expires_at,omitempty"`
	Metadata    map[string]interface{} `msgpack:"metadata,omitempty"`
}

// SRPChallenge represents a Secure Remote Password protocol challenge
type SRPChallenge struct {
	Protocol   string `msgpack:"protocol"`
	Service    string `msgpack:"service"`
	Challenge  []byte `msgpack:"challenge"`
	PublicKey  []byte `msgpack:"public_key"`
	ServerInfo []byte `msgpack:"server_info,omitempty"`
}

// SRPResponse represents a Secure Remote Password protocol response
type SRPResponse struct {
	Response   []byte `msgpack:"response"`
	PublicKey  []byte `msgpack:"public_key"`
	Proof      []byte `msgpack:"proof"`
	ClientInfo []byte `msgpack:"client_info,omitempty"`
}

// PRFRequest represents a pseudo-random function request
type PRFRequest struct {
	AppID  string `msgpack:"app_id"`
	Salt   []byte `msgpack:"salt"`
	Length int    `msgpack:"length,omitempty"`
}

// PRFResponse represents a pseudo-random function response
type PRFResponse struct {
	Output []byte `msgpack:"output"`
	AppID  string `msgpack:"app_id"`
}

// BackupMetadata contains metadata about a backup
type BackupMetadata struct {
	Version      int    `msgpack:"version"`
	CreatedAt    int64  `msgpack:"created_at"`
	IdentityType string `msgpack:"identity_type"`
	DID          string `msgpack:"did"`
}

// MigrationData represents data for migrating between protocol versions
type MigrationData struct {
	FromVersion int                    `msgpack:"from_version"`
	ToVersion   int                    `msgpack:"to_version"`
	OldID       []byte                 `msgpack:"old_id,omitempty"`
	NewID       []byte                 `msgpack:"new_id,omitempty"`
	Metadata    map[string]interface{} `msgpack:"metadata,omitempty"`
}

// ServiceKey represents a derived key for a specific service
type ServiceKey struct {
	Service   string `msgpack:"service"`
	Protocol  string `msgpack:"protocol"`
	PublicKey []byte `msgpack:"public_key"`
	CreatedAt int64  `msgpack:"created_at"`
}

// ProtocolKey represents a derived key for a specific protocol
type ProtocolKey struct {
	Protocol  string                 `msgpack:"protocol"`
	Version   int                    `msgpack:"version"`
	PublicKey []byte                 `msgpack:"public_key"`
	Metadata  map[string]interface{} `msgpack:"metadata,omitempty"`
}

// KeyDerivationParams contains parameters for key derivation
type KeyDerivationParams struct {
	Protocol string `msgpack:"protocol"`
	Service  string `msgpack:"service"`
	Salt     []byte `msgpack:"salt,omitempty"`
	Info     []byte `msgpack:"info,omitempty"`
	Length   int    `msgpack:"length"`
}

// DerivedKey represents a key derived for a specific purpose
type DerivedKey struct {
	Purpose   string `msgpack:"purpose"`
	Key       []byte `msgpack:"key"`
	PublicKey []byte `msgpack:"public_key,omitempty"`
	CreatedAt int64  `msgpack:"created_at"`
	ExpiresAt int64  `msgpack:"expires_at,omitempty"`
}

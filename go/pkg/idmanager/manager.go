package idmanager

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vmihailenco/msgpack/v5"
)

// ENCRYPTION_HEADER is the header for encrypted files
const ENCRYPTION_HEADER = "vaultys/encryption/\x01"

// PRF_NONCE_LENGTH is the length of the PRF nonce
const PRF_NONCE_LENGTH = 32

// StoredContact represents a stored contact in the IdManager
type StoredContact struct {
	ID          []byte                 `msgpack:"id" json:"id"`
	Certificate []byte                 `msgpack:"certificate,omitempty" json:"certificate,omitempty"`
	Metadata    map[string]interface{} `msgpack:"metadata,omitempty" json:"metadata,omitempty"`
	OldDID      string                 `msgpack:"oldDid,omitempty" json:"oldDid,omitempty"`
}

// StoredApp represents a stored application in the IdManager
type StoredApp struct {
	Site        string                 `msgpack:"site" json:"site"`
	ServerID    string                 `msgpack:"serverId" json:"serverId"` // Base64 encoded to match TypeScript
	Certificate []byte                 `msgpack:"certificate,omitempty" json:"certificate,omitempty"`
	Timestamp   int64                  `msgpack:"timestamp" json:"timestamp"`
	Metadata    map[string]interface{} `msgpack:"metadata,omitempty" json:"metadata,omitempty"`
	OldDID      string                 `msgpack:"oldDid,omitempty" json:"oldDid,omitempty"`
}

// FileSignature represents a file signature
type FileSignature struct {
	Challenge []byte `msgpack:"challenge" json:"challenge"`
	Signature []byte `msgpack:"signature" json:"signature"`
}

// File represents an encrypted or signed file
type File struct {
	Name        string `msgpack:"name" json:"name"`
	Type        string `msgpack:"type" json:"type"`
	ArrayBuffer []byte `msgpack:"arrayBuffer" json:"arrayBuffer"`
}

// ExportData represents the exported backup data structure
type ExportData struct {
	Version int         `msgpack:"version"`
	Data    interface{} `msgpack:"data"`
}

// Manager manages identities, contacts, and applications
type Manager struct {
	vaultysID *vaultysid.VaultysID
	store     Store
	mu        sync.RWMutex
}

// ErrEmptyPassword is returned when a backup is exported or imported with
// an empty password.
var ErrEmptyPassword = errors.New("backup password must not be empty")

// NewManager creates a new IdManager
func NewManager(id *vaultysid.VaultysID, store Store) *Manager {
	m := &Manager{
		vaultysID: id,
		store:     store,
	}

	// Initialize metadata store if not present
	if m.store.Get("metadata") == nil {
		m.store.Set("metadata", make(map[string]interface{}))
	}

	// Store entropy or secret
	if entropy := m.getEntropy(); entropy != nil {
		m.store.Set("entropy", entropy)
	} else {
		secret, _ := id.GetSecret()
		m.store.Set("secret", secret)
	}

	m.store.Save()
	return m
}

// SetProtocolVersion is kept for API compatibility: only handshake
// protocol version 1 exists, any other value is rejected.
func (m *Manager) SetProtocolVersion(version int) error {
	if version != 1 {
		return fmt.Errorf("unsupported protocol version: %d (only 1 is supported)", version)
	}
	return nil
}

// ExportBackup exports the IdManager state as an encrypted backup
func (m *Manager) ExportBackup(password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get store data
	storeData, err := m.store.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to serialize store: %w", err)
	}

	exportData := ExportData{
		Version: 1,
		Data:    storeData,
	}

	// Serialize with MessagePack
	packed, err := msgpack.Marshal(exportData)
	if err != nil {
		return "", fmt.Errorf("failed to pack data: %w", err)
	}

	// Encrypt the backup
	encrypted, err := crypto.PasswordEncrypt(packed, password)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt backup: %w", err)
	}

	// Return base64 encoded
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// ImportBackup imports an encrypted backup and creates a new Manager
func ImportBackup(backup string, password string) (*Manager, error) {
	if password == "" {
		return nil, ErrEmptyPassword
	}
	// Decode from base64
	encrypted, err := base64.StdEncoding.DecodeString(backup)
	if err != nil {
		return nil, fmt.Errorf("failed to decode backup: %w", err)
	}

	// Decrypt
	decrypted, err := crypto.PasswordDecrypt(encrypted, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt backup: %w", err)
	}

	// Unpack
	var importData ExportData
	if err := msgpack.Unmarshal(decrypted, &importData); err != nil {
		return nil, fmt.Errorf("failed to unpack backup: %w", err)
	}

	// Create store from imported data
	store := NewMemoryStore()
	if err := store.FromJSON(importData.Data); err != nil {
		return nil, fmt.Errorf("failed to restore store: %w", err)
	}

	// Recreate VaultysID from stored data
	var id *vaultysid.VaultysID

	if entropy := store.Get("entropy"); entropy != nil {
		if entropyBytes, ok := entropy.([]byte); ok {
			// Determine identity type from stored data
			idType := vaultysid.TypeMachine // Default
			if metadata := store.Get("metadata"); metadata != nil {
				if m, ok := metadata.(map[string]interface{}); ok {
					if typeStr, ok := m["type"].(string); ok {
						switch typeStr {
						case "person":
							idType = vaultysid.TypePerson
						case "organization":
							idType = vaultysid.TypeOrganization
						}
					}
				}
			}
			id, err = vaultysid.FromEntropy(entropyBytes, idType)
			if err != nil {
				return nil, fmt.Errorf("failed to recreate identity from entropy: %w", err)
			}
		}
	} else if secret := store.Get("secret"); secret != nil {
		if secretBytes, ok := secret.([]byte); ok {
			id, err = vaultysid.FromSecret(secretBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to recreate identity from secret: %w", err)
			}
		}
	}

	if id == nil {
		return nil, fmt.Errorf("no identity found in backup")
	}

	return NewManager(id, store), nil
}

// Contacts returns all contacts
func (m *Manager) Contacts() []StoredContact {
	m.mu.RLock()
	defer m.mu.RUnlock()

	store := m.store.Substore("contacts")
	contacts := make([]StoredContact, 0)

	for _, key := range store.List() {
		if data := store.Get(key); data != nil {
			if contact, ok := data.(StoredContact); ok {
				contacts = append(contacts, contact)
			} else if contactMap, ok := data.(map[string]interface{}); ok {
				// Try to reconstruct StoredContact from map
				contact := m.mapToContact(contactMap)
				contacts = append(contacts, contact)
			}
		}
	}

	return contacts
}

// Apps returns all applications
func (m *Manager) Apps() []StoredApp {
	m.mu.RLock()
	defer m.mu.RUnlock()

	apps := make([]StoredApp, 0)

	// Check both "apps" and "registrations" substores for compatibility
	// "apps" is used by legacy string API, "registrations" is used by VaultysID API
	for _, storeName := range []string{"apps", "registrations"} {
		store := m.store.Substore(storeName)
		for _, key := range store.List() {
			if data := store.Get(key); data != nil {
				if app, ok := data.(StoredApp); ok {
					apps = append(apps, app)
				} else if appMap, ok := data.(map[string]interface{}); ok {
					// Try to reconstruct StoredApp from map
					app := m.mapToApp(appMap)
					apps = append(apps, app)
				}
			}
		}
	}

	return apps
}

// GetContact retrieves a contact by DID
func (m *Manager) GetContact(did string) (*vaultysid.VaultysID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	store := m.store.Substore("contacts")
	data := store.Get(did)
	if data == nil {
		return nil, fmt.Errorf("contact not found: %s", did)
	}

	var contact StoredContact
	switch v := data.(type) {
	case StoredContact:
		contact = v
	case map[string]interface{}:
		contact = m.mapToContact(v)
	default:
		return nil, fmt.Errorf("invalid contact data type")
	}

	return m.instantiateContact(contact)
}

// GetApp retrieves an application by site
func (m *Manager) GetApp(site string) (*StoredApp, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	store := m.store.Substore("apps")
	data := store.Get(site)
	if data == nil {
		return nil, fmt.Errorf("app not found: %s", site)
	}

	switch v := data.(type) {
	case StoredApp:
		return &v, nil
	case map[string]interface{}:
		app := m.mapToApp(v)
		return &app, nil
	default:
		return nil, fmt.Errorf("invalid app data type")
	}
}

// SetContactMetadata sets metadata for a contact
func (m *Manager) SetContactMetadata(did string, key string, value interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	store := m.store.Substore("contacts")
	data := store.Get(did)
	if data == nil {
		return fmt.Errorf("contact not found: %s", did)
	}

	var contact StoredContact
	switch v := data.(type) {
	case StoredContact:
		contact = v
	case map[string]interface{}:
		contact = m.mapToContact(v)
	}

	if contact.Metadata == nil {
		contact.Metadata = make(map[string]interface{})
	}
	contact.Metadata[key] = value

	store.Set(did, contact)
	return m.store.Save()
}

// GetContactMetadata gets a specific metadata value for a contact
func (m *Manager) GetContactMetadata(did string, key string) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	store := m.store.Substore("contacts")
	data := store.Get(did)
	if data == nil {
		return nil, fmt.Errorf("contact not found: %s", did)
	}

	var contact StoredContact
	switch v := data.(type) {
	case StoredContact:
		contact = v
	case map[string]interface{}:
		contact = m.mapToContact(v)
	}

	if contact.Metadata == nil {
		return nil, nil
	}

	return contact.Metadata[key], nil
}

// Name property
func (m *Manager) SetName(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	metadata := m.getOrCreateMetadata()
	metadata["name"] = name
	m.store.Set("metadata", metadata)
	return m.store.Save()
}

func (m *Manager) Name() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if metadata := m.getMetadata(); metadata != nil {
		if name, ok := metadata["name"].(string); ok {
			return name
		}
	}
	return ""
}

// DisplayName returns the display name (name or truncated DID)
func (m *Manager) DisplayName() string {
	if name := m.Name(); name != "" {
		return name
	}

	did := m.vaultysID.DID()
	if len(did) > 20 {
		return did[:20] + "..."
	}
	return did
}

// Phone property
func (m *Manager) SetPhone(phone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	metadata := m.getOrCreateMetadata()
	metadata["phone"] = phone
	m.store.Set("metadata", metadata)
	return m.store.Save()
}

func (m *Manager) Phone() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if metadata := m.getMetadata(); metadata != nil {
		if phone, ok := metadata["phone"].(string); ok {
			return phone
		}
	}
	return ""
}

// Email property
func (m *Manager) SetEmail(email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	metadata := m.getOrCreateMetadata()
	metadata["email"] = email
	m.store.Set("metadata", metadata)
	return m.store.Save()
}

func (m *Manager) Email() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if metadata := m.getMetadata(); metadata != nil {
		if email, ok := metadata["email"].(string); ok {
			return email
		}
	}
	return ""
}

// SignChallenge signs an application challenge (SHA-256("VAULTYS_SIGN" || challenge)).
func (m *Manager) SignChallenge(challenge []byte) ([]byte, error) {
	return m.vaultysID.SignChallenge(challenge)
}

// VerifyChallenge verifies a signature produced by SignChallenge.
func (m *Manager) VerifyChallenge(challenge []byte, signature []byte) error {
	return m.vaultysID.VerifyChallenge(challenge, signature)
}

// SignFile signs a file and returns a FileSignature
func (m *Manager) SignFile(file *File) (*FileSignature, error) {
	// Hash the file
	h := sha256.Sum256(file.ArrayBuffer)
	hashStr := hex.EncodeToString(h[:])

	// Create challenge URL like TypeScript
	timestamp := crypto.Now()
	challenge := []byte(fmt.Sprintf("vaultys://signfile?hash=%s&timestamp=%d", hashStr, timestamp))

	// Sign the challenge
	signature, err := m.vaultysID.SignChallenge(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to sign file: %w", err)
	}

	// Store signature in substore like TypeScript
	sigStore := m.store.Substore("signatures")
	sigStore.Set(fmt.Sprintf("%d", timestamp), map[string]interface{}{
		"challenge": challenge,
		"signature": signature,
	})
	m.store.Save()

	return &FileSignature{
		Challenge: challenge,
		Signature: signature,
	}, nil
}

// VerifyFile verifies a file signature
func (m *Manager) VerifyFile(file *File, signature *FileSignature, contactID *vaultysid.VaultysID, userVerification bool) error {
	// TypeScript FileSignature already contains the challenge
	challenge := signature.Challenge

	// If challenge is nil, try to get from stored signatures
	if challenge == nil {
		sigStore := m.store.Substore("signatures")
		for _, key := range sigStore.List() {
			if data := sigStore.Get(key); data != nil {
				if sig, ok := data.(map[string]interface{}); ok {
					if storedSig, ok := sig["signature"].([]byte); ok {
						if bytes.Equal(storedSig, signature.Signature) {
							if ch, ok := sig["challenge"].([]byte); ok {
								challenge = ch
								break
							}
						}
					}
				}
			}
		}
	}

	// If still no challenge, we can't verify
	if challenge == nil {
		return fmt.Errorf("no challenge found in signature")
	}

	// The signed challenge must be a signfile URL committing to exactly
	// this file: exactly one `hash` parameter equal to its SHA-256.
	if err := checkSignFileChallenge(challenge, file.ArrayBuffer); err != nil {
		return err
	}

	// Use the provided contact VaultysID for verification
	if contactID != nil {
		return contactID.VerifyChallenge(challenge, signature.Signature)
	}

	// No fallback without contact ID
	return fmt.Errorf("contact ID required for verification")
}

// checkSignFileChallenge parses a "vaultys://signfile?hash=...&timestamp=..."
// challenge and fails closed unless it carries exactly one hash parameter
// equal to the hex SHA-256 of data.
func checkSignFileChallenge(challenge []byte, data []byte) error {
	u, err := url.Parse(string(challenge))
	if err != nil {
		return fmt.Errorf("invalid challenge format: %w", err)
	}
	if u.Scheme != "vaultys" || u.Host != "signfile" || (u.Path != "" && u.Path != "/") || u.Opaque != "" || u.Fragment != "" {
		return fmt.Errorf("invalid challenge format")
	}
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("invalid challenge query: %w", err)
	}
	hashes := params["hash"]
	if len(hashes) != 1 {
		return fmt.Errorf("file hash mismatch: challenge must contain exactly one hash")
	}
	h := sha256.Sum256(data)
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(hashes[0])), []byte(hex.EncodeToString(h[:]))) != 1 {
		return fmt.Errorf("file hash mismatch")
	}
	return nil
}

// EncryptFile encrypts a file for storage
func (m *Manager) EncryptFile(file *File) (*File, error) {
	// Generate PRF nonce
	prfNonce, err := crypto.RandomBytes(PRF_NONCE_LENGTH)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PRF nonce: %w", err)
	}

	// Generate PRF like TypeScript: vaultysId.hmac("prf|encryption/<hex>/encryption|prf")
	prfInput := fmt.Sprintf("prf|encryption/%s/encryption|prf", hex.EncodeToString(prfNonce))
	prf, err := m.vaultysID.HMAC(prfInput)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PRF: %w", err)
	}

	// PRF should be exactly 32 bytes (HMAC-SHA256 output)
	if len(prf) != PRF_NONCE_LENGTH {
		return nil, fmt.Errorf("invalid PRF length: got %d, expected %d", len(prf), PRF_NONCE_LENGTH)
	}

	// Use sha256 hash of PRF as secretbox key (32 bytes)
	secretKeyHash := sha256.Sum256(prf)
	secretKey := secretKeyHash[:]

	// Generate encryption nonce
	nonce, err := crypto.RandomBytes(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the file data
	ciphertext, err := crypto.Encrypt(file.ArrayBuffer, secretKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt file: %w", err)
	}

	// Build result: header + prfNonce + nonce + ciphertext
	var result bytes.Buffer
	result.WriteString(ENCRYPTION_HEADER)
	result.Write(prfNonce)
	result.Write(nonce)
	result.Write(ciphertext)

	return &File{
		Name:        file.Name,
		Type:        file.Type,
		ArrayBuffer: result.Bytes(),
	}, nil
}

// DecryptFile decrypts an encrypted file - matches TypeScript's implementation
func (m *Manager) DecryptFile(encryptedFile *File) (*File, error) {
	data := encryptedFile.ArrayBuffer

	// Check header
	if len(data) < len(ENCRYPTION_HEADER) {
		return nil, fmt.Errorf("invalid encrypted file: too short")
	}

	header := data[:len(ENCRYPTION_HEADER)]
	if !bytes.Equal(header, []byte(ENCRYPTION_HEADER)) {
		return nil, fmt.Errorf("invalid header for encrypted file")
	}

	// Extract components
	offset := len(ENCRYPTION_HEADER)
	if len(data) < offset+PRF_NONCE_LENGTH+24 {
		return nil, fmt.Errorf("invalid encrypted file: insufficient data")
	}

	prfNonce := data[offset : offset+PRF_NONCE_LENGTH]
	offset += PRF_NONCE_LENGTH

	nonce := data[offset : offset+24]
	offset += 24

	ciphertext := data[offset:]

	// Generate PRF like TypeScript: vaultysId.hmac("prf|encryption/<hex>/encryption|prf")
	prfInput := fmt.Sprintf("prf|encryption/%s/encryption|prf", hex.EncodeToString(prfNonce))
	prf, err := m.vaultysID.HMAC(prfInput)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PRF: %w", err)
	}

	// PRF should be exactly 32 bytes (HMAC-SHA256 output)
	if len(prf) != PRF_NONCE_LENGTH {
		return nil, fmt.Errorf("invalid PRF length: got %d, expected %d", len(prf), PRF_NONCE_LENGTH)
	}

	// Use sha256 hash of PRF as secretbox key (32 bytes)
	secretKeyHash := sha256.Sum256(prf)
	secretKey := secretKeyHash[:]

	// Decrypt using secretbox
	plaintext, err := crypto.Decrypt(ciphertext, secretKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("decryption failed")
	}

	return &File{
		Name:        encryptedFile.Name,
		Type:        encryptedFile.Type,
		ArrayBuffer: plaintext,
	}, nil
}

// PRF generates a pseudo-random function output for a given app and salt
func (m *Manager) PRF(appID string, salt []byte) ([]byte, error) {
	// Match TypeScript's PRF implementation
	// TypeScript uses: this.vaultysId.hmac("prf|" + appID + "|" + salt + "|prf")
	input := fmt.Sprintf("prf|%s|%s|prf", appID, hex.EncodeToString(salt))

	// Use the VaultysID's HMAC method
	result, err := m.vaultysID.HMAC(input)
	if err != nil {
		return nil, fmt.Errorf("failed to compute PRF: %w", err)
	}

	// HMAC-SHA256 always returns 32 bytes, which matches PRF_NONCE_LENGTH
	return result, nil
}

// SaveContact saves a contact to the store
func (m *Manager) SaveContact(contact *vaultysid.VaultysID, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveContactLocked(contact, metadata)
}

// saveContactLocked is the implementation of SaveContact. Callers must hold m.mu;
// it exists so SaveApp can dispatch here without recursively re-locking m.mu
// (sync.RWMutex isn't reentrant, so calling SaveContact/SaveApp from within
// each other via the public locking methods would deadlock).
func (m *Manager) saveContactLocked(contact *vaultysid.VaultysID, metadata map[string]interface{}) error {
	// Match TypeScript: convert to same version
	// contact.toVersion(this.vaultysId.version)

	if contact.IsMachine() {
		// If it's a machine, save as app instead
		return m.saveAppLocked(contact)
	}

	did := contact.DID()
	stored := StoredContact{
		ID:          contact.ID(),
		Certificate: contact.Certificate,
		Metadata:    metadata,
	}

	contactStore := m.store.Substore("contacts")
	if contactStore.Get(did) == nil {
		contactStore.Set(did, stored)
		return m.store.Save()
	}

	return nil
}

// SaveApp saves an application to the store - supports both raw parameters and VaultysID
func (m *Manager) SaveApp(app interface{}, name ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveAppLocked(app, name...)
}

// saveAppLocked is the implementation of SaveApp. Callers must hold m.mu; see
// saveContactLocked for why this split exists.
func (m *Manager) saveAppLocked(app interface{}, name ...string) error {
	switch v := app.(type) {
	case *vaultysid.VaultysID:
		// TypeScript-style API with VaultysID
		if !v.IsMachine() {
			// If not a machine, save as contact instead
			return m.saveContactLocked(v, nil)
		}

		appStore := m.store.Substore("registrations")
		siteName := v.DID()
		if len(name) > 0 && name[0] != "" {
			siteName = name[0]
		}

		if appStore.Get(v.DID()) == nil {
			stored := StoredApp{
				Site:        siteName,
				ServerID:    base64.StdEncoding.EncodeToString(v.ID()),
				Certificate: v.Certificate,
				Timestamp:   crypto.Now(),
			}
			appStore.Set(v.DID(), stored)
		}
		return m.store.Save()

	case string:
		// Legacy API with site string and raw parameters
		site := v
		var serverID []byte
		var certificate []byte

		if len(name) > 0 {
			// Second parameter is serverID as hex string
			if sid, err := hex.DecodeString(name[0]); err == nil {
				serverID = sid
			}
		}

		stored := StoredApp{
			Site:        site,
			ServerID:    base64.StdEncoding.EncodeToString(serverID),
			Certificate: certificate,
			Timestamp:   crypto.Now(),
		}

		appStore := m.store.Substore("apps")
		appStore.Set(site, stored)
		return m.store.Save()

	default:
		return fmt.Errorf("invalid app parameter type")
	}
}

// Connect protocol/service used by RequestConnect / AcceptConnect.
const (
	ConnectProtocol = "p2p"
	ConnectService  = "auth"
)

// ConnectSession is one side of a RequestConnect / AcceptConnect handshake.
//
// The connection is a plain mutual-authentication handshake (protocol
// "p2p", service "auth"); no Diffie-Hellman output or other secret is ever
// placed in a challenge field. Once the handshake is COMPLETE the
// authenticated remote identity is saved as a contact (or app), together
// with the handshake certificate.
type ConnectSession struct {
	manager  *Manager
	ch       *challenger.Challenger
	expected []byte // optional expected remote id (initiator side)
}

// RequestConnect starts a connection as initiator and returns the session
// plus the INIT message to send. If contact is non-nil, the handshake only
// completes with that exact identity.
func (m *Manager) RequestConnect(contact *vaultysid.VaultysID) (*ConnectSession, []byte, error) {
	s := &ConnectSession{manager: m}
	if contact != nil {
		s.expected = contact.ID()
	}
	s.ch = challenger.NewChallenger(m.vaultysID, &challenger.ChallengerOptions{
		Accept: func(remote *vaultysid.VaultysID, protocol, service string) error {
			if s.expected != nil && !bytes.Equal(remote.ID(), s.expected) {
				return fmt.Errorf("remote is not the requested contact")
			}
			return nil
		},
	})
	init, err := s.ch.Init(ConnectProtocol, ConnectService)
	if err != nil {
		return nil, nil, err
	}
	msg, err := challenger.Serialize(init)
	if err != nil {
		return nil, nil, err
	}
	return s, msg, nil
}

// Complete (initiator) processes the responder's STEP1 message, saves the
// authenticated contact and returns the COMPLETE message to send back.
func (s *ConnectSession) Complete(step1 []byte) ([]byte, *vaultysid.VaultysID, error) {
	resp, err := s.ch.Accept(step1)
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || !s.ch.IsComplete() {
		return nil, nil, fmt.Errorf("unexpected message: expected STEP1")
	}
	contact, err := s.saveRemote()
	if err != nil {
		return nil, nil, err
	}
	msg, err := challenger.Serialize(resp)
	if err != nil {
		return nil, nil, err
	}
	return msg, contact, nil
}

// AcceptConnect processes an INIT message as responder and returns the
// session plus the STEP1 message to send back. The first message must be an
// INIT for protocol "p2p" / service "auth". accept, if non-nil, is given
// the REMOTE (initiator's) identity and may refuse it.
func (m *Manager) AcceptConnect(initMsg []byte, accept func(remote *vaultysid.VaultysID) error) (*ConnectSession, []byte, error) {
	init, err := challenger.Deserialize(initMsg)
	if err != nil {
		return nil, nil, err
	}
	if init.State != challenger.StateInit {
		return nil, nil, fmt.Errorf("first connect message must be INIT")
	}
	if init.Protocol != ConnectProtocol || init.Service != ConnectService {
		return nil, nil, fmt.Errorf("unexpected protocol/service %q/%q", init.Protocol, init.Service)
	}
	s := &ConnectSession{manager: m}
	s.ch = challenger.NewChallenger(m.vaultysID, &challenger.ChallengerOptions{
		Accept: func(remote *vaultysid.VaultysID, protocol, service string) error {
			if accept != nil {
				return accept(remote)
			}
			return nil
		},
	})
	step1, err := s.ch.Step1(init)
	if err != nil {
		return nil, nil, err
	}
	msg, err := challenger.Serialize(step1)
	if err != nil {
		return nil, nil, err
	}
	return s, msg, nil
}

// Finalize (responder) processes the initiator's COMPLETE message and saves
// the authenticated contact.
func (s *ConnectSession) Finalize(complete []byte) (*vaultysid.VaultysID, error) {
	if _, err := s.ch.Accept(complete); err != nil {
		return nil, err
	}
	if !s.ch.IsComplete() {
		return nil, fmt.Errorf("unexpected message: expected COMPLETE")
	}
	return s.saveRemote()
}

// Challenger exposes the underlying handshake state (read-only use).
func (s *ConnectSession) Challenger() *challenger.Challenger {
	return s.ch
}

func (s *ConnectSession) saveRemote() (*vaultysid.VaultysID, error) {
	remote, err := s.ch.GetRemoteVaultysID()
	if err != nil {
		return nil, err
	}
	if err := s.manager.SaveContact(remote, nil); err != nil {
		return nil, fmt.Errorf("failed to save contact: %w", err)
	}
	return remote, nil
}

// IsHardware returns true if the identity is hardware-backed
func (m *Manager) IsHardware() bool {
	return m.vaultysID.IsHardware()
}

// Helper methods

func (m *Manager) getEntropy() []byte {
	// This would need to be implemented based on the key manager type
	// For now, return nil to use secret instead
	return nil
}

func (m *Manager) getMetadata() map[string]interface{} {
	if metadata := m.store.Get("metadata"); metadata != nil {
		if m, ok := metadata.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

func (m *Manager) getOrCreateMetadata() map[string]interface{} {
	metadata := m.getMetadata()
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	return metadata
}

func (m *Manager) instantiateContact(stored StoredContact) (*vaultysid.VaultysID, error) {
	return vaultysid.FromID(stored.ID, stored.Certificate)
}

func (m *Manager) mapToContact(data map[string]interface{}) StoredContact {
	contact := StoredContact{
		Metadata: make(map[string]interface{}),
	}

	// Handle ID - can be []byte or base64-encoded string from JSON
	if id, ok := data["id"].([]byte); ok {
		contact.ID = id
	} else if idStr, ok := data["id"].(string); ok {
		if decoded, err := base64.StdEncoding.DecodeString(idStr); err == nil {
			contact.ID = decoded
		}
	}
	// Handle certificate - can be []byte or base64-encoded string from JSON
	if cert, ok := data["certificate"].([]byte); ok {
		contact.Certificate = cert
	} else if certStr, ok := data["certificate"].(string); ok {
		if decoded, err := base64.StdEncoding.DecodeString(certStr); err == nil {
			contact.Certificate = decoded
		}
	}
	if meta, ok := data["metadata"].(map[string]interface{}); ok {
		contact.Metadata = meta
	}
	if oldDID, ok := data["oldDid"].(string); ok {
		contact.OldDID = oldDID
	}

	return contact
}

func (m *Manager) mapToApp(data map[string]interface{}) StoredApp {
	app := StoredApp{}

	if site, ok := data["site"].(string); ok {
		app.Site = site
	}
	if serverID, ok := data["serverId"].([]byte); ok {
		app.ServerID = base64.StdEncoding.EncodeToString(serverID)
	} else if serverID, ok := data["serverId"].(string); ok {
		app.ServerID = serverID
	}
	// Handle certificate - can be []byte or base64-encoded string from JSON
	if cert, ok := data["certificate"].([]byte); ok {
		app.Certificate = cert
	} else if certStr, ok := data["certificate"].(string); ok {
		if decoded, err := base64.StdEncoding.DecodeString(certStr); err == nil {
			app.Certificate = decoded
		}
	}
	if ts, ok := data["timestamp"].(int64); ok {
		app.Timestamp = ts
	}
	if meta, ok := data["metadata"].(map[string]interface{}); ok {
		app.Metadata = meta
	}
	if oldDID, ok := data["oldDid"].(string); ok {
		app.OldDID = oldDID
	}

	return app
}

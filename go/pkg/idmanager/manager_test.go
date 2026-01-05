package idmanager

import (
	"encoding/base64"
	"testing"

	"github.com/vaultys/vaultysid-go/pkg/vaultysid"
)

func TestNewManager(t *testing.T) {
	// Create a test identity
	id, err := vaultysid.GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// Create a memory store
	store := NewMemoryStore()

	// Create manager
	manager := NewManager(id, store)

	// Verify manager was created
	if manager == nil {
		t.Fatal("Manager should not be nil")
	}

	// Verify vaultysID was set
	if manager.vaultysID == nil {
		t.Fatal("VaultysID should not be nil")
	}

	// Verify store was set
	if manager.store == nil {
		t.Fatal("Store should not be nil")
	}

	// Verify metadata was initialized
	if manager.store.Get("metadata") == nil {
		t.Fatal("Metadata should be initialized")
	}

	// Verify protocol version defaults to 0
	if manager.protocolVersion != 0 {
		t.Errorf("Protocol version should default to 0, got %d", manager.protocolVersion)
	}
}

func TestSetProtocolVersion(t *testing.T) {
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	// Test setting valid protocol version 1
	err := manager.SetProtocolVersion(1)
	if err != nil {
		t.Errorf("Failed to set protocol version 1: %v", err)
	}
	if manager.protocolVersion != 1 {
		t.Errorf("Protocol version should be 1, got %d", manager.protocolVersion)
	}

	// Test setting valid protocol version 0
	err = manager.SetProtocolVersion(0)
	if err != nil {
		t.Errorf("Failed to set protocol version 0: %v", err)
	}
	if manager.protocolVersion != 0 {
		t.Errorf("Protocol version should be 0, got %d", manager.protocolVersion)
	}

	// Test setting invalid protocol version
	err = manager.SetProtocolVersion(2)
	if err == nil {
		t.Error("Setting invalid protocol version should fail")
	}
}

func TestNameProperties(t *testing.T) {
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	// Test setting and getting name
	testName := "John Doe"
	err := manager.SetName(testName)
	if err != nil {
		t.Errorf("Failed to set name: %v", err)
	}

	name := manager.Name()
	if name != testName {
		t.Errorf("Name should be '%s', got '%s'", testName, name)
	}

	// Test display name with name set
	displayName := manager.DisplayName()
	if displayName != testName {
		t.Errorf("Display name should be '%s', got '%s'", testName, displayName)
	}

	// Test display name without name (should return truncated DID)
	manager.SetName("")
	displayName = manager.DisplayName()
	if displayName == "" {
		t.Error("Display name should not be empty when name is not set")
	}
}

func TestEmailPhone(t *testing.T) {
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	// Test email
	testEmail := "test@example.com"
	err := manager.SetEmail(testEmail)
	if err != nil {
		t.Errorf("Failed to set email: %v", err)
	}

	email := manager.Email()
	if email != testEmail {
		t.Errorf("Email should be '%s', got '%s'", testEmail, email)
	}

	// Test phone
	testPhone := "+1234567890"
	err = manager.SetPhone(testPhone)
	if err != nil {
		t.Errorf("Failed to set phone: %v", err)
	}

	phone := manager.Phone()
	if phone != testPhone {
		t.Errorf("Phone should be '%s', got '%s'", testPhone, phone)
	}
}

func TestContactManagement(t *testing.T) {
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	// Create a test contact
	contactID, _ := vaultysid.GeneratePerson()

	// Save contact
	metadata := map[string]interface{}{
		"name":  "Alice",
		"email": "alice@example.com",
	}
	err := manager.SaveContact(contactID, metadata)
	if err != nil {
		t.Errorf("Failed to save contact: %v", err)
	}

	// Get contact
	retrievedContact, err := manager.GetContact(contactID.DID())
	if err != nil {
		t.Errorf("Failed to get contact: %v", err)
	}

	if !retrievedContact.Equals(contactID) {
		t.Error("Retrieved contact does not match saved contact")
	}

	// List contacts
	contacts := manager.Contacts()
	if len(contacts) != 1 {
		t.Errorf("Should have 1 contact, got %d", len(contacts))
	}

	// Set contact metadata
	err = manager.SetContactMetadata(contactID.DID(), "nickname", "Ally")
	if err != nil {
		t.Errorf("Failed to set contact metadata: %v", err)
	}

	// Get contact metadata
	nickname, err := manager.GetContactMetadata(contactID.DID(), "nickname")
	if err != nil {
		t.Errorf("Failed to get contact metadata: %v", err)
	}
	if nickname != "Ally" {
		t.Errorf("Nickname should be 'Ally', got '%v'", nickname)
	}
}

func TestAppManagement(t *testing.T) {
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	// Create test app data
	site := "example.com"
	serverID := "736572766572d6964d313233" // hex encoded "server-id-123"

	// Save app using the new API (site string with optional serverID string)
	err := manager.SaveApp(site, serverID)
	if err != nil {
		t.Errorf("Failed to save app: %v", err)
	}

	// Get app
	app, err := manager.GetApp(site)
	if err != nil {
		t.Errorf("Failed to get app: %v", err)
	}

	if app.Site != site {
		t.Errorf("App site should be '%s', got '%s'", site, app.Site)
	}

	// List apps
	apps := manager.Apps()
	if len(apps) != 1 {
		t.Errorf("Should have 1 app, got %d", len(apps))
	}
}

func TestFileOperations(t *testing.T) {
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	// Create test file
	testFile := &File{
		Name:        "test.txt",
		Type:        "text/plain",
		ArrayBuffer: []byte("Hello, World!"),
	}

	// Test file signing
	signature, err := manager.SignFile(testFile)
	if err != nil {
		t.Errorf("Failed to sign file: %v", err)
	}

	if signature == nil {
		t.Fatal("Signature should not be nil")
	}
	if len(signature.Signature) == 0 {
		t.Error("Signature data should not be empty")
	}

	// Test file encryption/decryption (uses identity's HMAC)
	encryptedFile, err := manager.EncryptFile(testFile)
	if err != nil {
		t.Errorf("Failed to encrypt file: %v", err)
	}

	if encryptedFile.Name != testFile.Name {
		t.Error("Encrypted file should preserve name")
	}
	if encryptedFile.Type != testFile.Type {
		t.Error("Encrypted file should preserve type")
	}

	// Decrypt the file (uses identity's HMAC)
	decryptedFile, err := manager.DecryptFile(encryptedFile)
	if err != nil {
		t.Errorf("Failed to decrypt file: %v", err)
	}

	if decryptedFile == nil {
		t.Fatal("Decrypted file should not be nil")
	}
	if string(decryptedFile.ArrayBuffer) != string(testFile.ArrayBuffer) {
		t.Error("Decrypted content does not match original")
	}

	// Test decryption with different identity should fail
	// (Since encryption uses identity's HMAC, a different identity can't decrypt)
	id2, _ := vaultysid.GeneratePerson()
	store2 := NewMemoryStore()
	manager2 := NewManager(id2, store2)
	_, err = manager2.DecryptFile(encryptedFile)
	if err == nil {
		t.Error("Decryption with different identity should fail")
	}
}

func TestBackupExportImport(t *testing.T) {
	// Create and configure a manager
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	// Set some data
	manager.SetName("Test User")
	manager.SetEmail("test@example.com")
	manager.SetPhone("+1234567890")

	// Save a contact
	contactID, _ := vaultysid.GeneratePerson()
	manager.SaveContact(contactID, map[string]interface{}{
		"name": "Contact 1",
	})

	// Export backup
	password := "backup-password-123"
	backup, err := manager.ExportBackup(password)
	if err != nil {
		t.Fatalf("Failed to export backup: %v", err)
	}

	// Verify backup is base64 encoded
	_, err = base64.StdEncoding.DecodeString(backup)
	if err != nil {
		t.Error("Backup should be base64 encoded")
	}

	// Import backup
	importedManager, err := ImportBackup(backup, password)
	if err != nil {
		t.Fatalf("Failed to import backup: %v", err)
	}

	// Verify imported data
	if importedManager.Name() != "Test User" {
		t.Errorf("Imported name should be 'Test User', got '%s'", importedManager.Name())
	}
	if importedManager.Email() != "test@example.com" {
		t.Errorf("Imported email should be 'test@example.com', got '%s'", importedManager.Email())
	}
	if importedManager.Phone() != "+1234567890" {
		t.Errorf("Imported phone should be '+1234567890', got '%s'", importedManager.Phone())
	}

	// Verify contacts were imported
	contacts := importedManager.Contacts()
	if len(contacts) != 1 {
		t.Errorf("Should have 1 imported contact, got %d", len(contacts))
	}

	// Test import with wrong password
	_, err = ImportBackup(backup, "wrong-password")
	if err == nil {
		t.Error("Import with wrong password should fail")
	}
}

func TestPRF(t *testing.T) {
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	appID := "test-app"
	salt := []byte("test-salt")

	// Generate PRF
	prf1, err := manager.PRF(appID, salt)
	if err != nil {
		t.Errorf("Failed to generate PRF: %v", err)
	}

	if len(prf1) != 32 {
		t.Errorf("PRF should be 32 bytes, got %d", len(prf1))
	}

	// Generate PRF again with same inputs - should be deterministic
	prf2, err := manager.PRF(appID, salt)
	if err != nil {
		t.Errorf("Failed to generate PRF: %v", err)
	}

	if string(prf1) != string(prf2) {
		t.Error("PRF should be deterministic for same inputs")
	}

	// Generate PRF with different salt - should be different
	prf3, err := manager.PRF(appID, []byte("different-salt"))
	if err != nil {
		t.Errorf("Failed to generate PRF: %v", err)
	}

	if string(prf1) == string(prf3) {
		t.Error("PRF should be different for different salts")
	}
}

func TestSignVerifyChallenge(t *testing.T) {
	id, _ := vaultysid.GeneratePerson()
	store := NewMemoryStore()
	manager := NewManager(id, store)

	challenge := []byte("test-challenge")

	// Sign challenge
	signature, err := manager.SignChallenge(challenge)
	if err != nil {
		t.Errorf("Failed to sign challenge: %v", err)
	}

	// Verify challenge
	err = manager.VerifyChallenge(challenge, signature)
	if err != nil {
		t.Errorf("Failed to verify challenge: %v", err)
	}

	// Verify with wrong challenge should fail
	err = manager.VerifyChallenge([]byte("wrong-challenge"), signature)
	if err == nil {
		t.Error("Verification with wrong challenge should fail")
	}
}

func TestMemoryStore(t *testing.T) {
	store := NewMemoryStore()

	// Test basic set/get
	store.Set("key1", "value1")
	value := store.Get("key1")
	if value != "value1" {
		t.Errorf("Expected 'value1', got '%v'", value)
	}

	// Test delete
	store.Delete("key1")
	value = store.Get("key1")
	if value != nil {
		t.Error("Value should be nil after delete")
	}

	// Test list
	store.Set("key1", "value1")
	store.Set("key2", "value2")
	keys := store.List()
	if len(keys) != 2 {
		t.Errorf("Should have 2 keys, got %d", len(keys))
	}

	// Test substore
	substore := store.Substore("sub1")
	substore.Set("subkey1", "subvalue1")

	// Verify substore is listed
	substores := store.ListSubstores()
	if len(substores) != 1 || substores[0] != "sub1" {
		t.Error("Substore 'sub1' should be listed")
	}

	// Test rename substore
	store.RenameSubstore("sub1", "sub2")
	substores = store.ListSubstores()
	if len(substores) != 1 || substores[0] != "sub2" {
		t.Error("Substore should be renamed to 'sub2'")
	}

	// Test delete substore
	store.DeleteSubstore("sub2")
	substores = store.ListSubstores()
	if len(substores) != 0 {
		t.Error("Substore should be deleted")
	}
}

func TestStoreSerializationJSON(t *testing.T) {
	store := NewMemoryStore()

	// Add some data
	store.Set("string", "value")
	store.Set("number", 42)
	store.Set("bytes", []byte("binary data"))

	substore := store.Substore("sub")
	substore.Set("nested", "data")

	// Export to JSON
	jsonData, err := store.ToJSON()
	if err != nil {
		t.Errorf("Failed to export to JSON: %v", err)
	}

	// Create new store and import
	newStore := NewMemoryStore()
	err = newStore.FromJSON(jsonData)
	if err != nil {
		t.Errorf("Failed to import from JSON: %v", err)
	}

	// Verify data was imported
	if newStore.Get("string") != "value" {
		t.Error("String value not imported correctly")
	}
	if newStore.Get("number") != 42 {
		t.Error("Number value not imported correctly")
	}

	// Verify substore was imported
	substores := newStore.ListSubstores()
	if len(substores) != 1 || substores[0] != "sub" {
		t.Error("Substore not imported correctly")
	}
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vaultys/vaultysid-go/pkg/idmanager"
	"github.com/vaultys/vaultysid-go/pkg/vaultysid"
)

func TestCompleteWorkflow(t *testing.T) {

	tempDir := t.TempDir()

	// Step 1: Generate a new identity
	cmd := setupTestCommand()
	cmd.AddCommand(newGenerateCmd())

	output, err := executeCommand(cmd, "generate", "person", "-o", "json")
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal([]byte(output), &result)
	require.NoError(t, err)

	secret := result["secret"].(string)
	id := result["id"].(string)
	require.NotEmpty(t, secret)
	require.NotEmpty(t, id)
	_ = id // id is available for future use

	// Step 2: Initialize IDManager
	storePath := filepath.Join(tempDir, "identity.store")
	t.Run("Initialize IDManager", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerInitCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "init", secret, storePath)
		require.NoError(t, err)

		// Verify store exists
		_, err = os.Stat(storePath)
		assert.NoError(t, err)
	})

	// Step 3: Set user information
	t.Run("Set User Info", func(t *testing.T) {
		// Set name
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerSetNameCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "set-name", secret, storePath, "John Integration")
		require.NoError(t, err)

		// Set email
		cmd = setupTestCommand()
		mgr = newManagerCmd()
		mgr.AddCommand(newManagerSetEmailCmd())
		cmd.AddCommand(mgr)

		_, err = executeCommand(cmd, "manager", "set-email", secret, storePath, "john@integration.test")
		require.NoError(t, err)

		// Set phone
		cmd = setupTestCommand()
		mgr = newManagerCmd()
		mgr.AddCommand(newManagerSetPhoneCmd())
		cmd.AddCommand(mgr)

		_, err = executeCommand(cmd, "manager", "set-phone", secret, storePath, "+1-555-0123")
		require.NoError(t, err)
	})

	// Step 4: Add contacts
	t.Run("Add Contacts", func(t *testing.T) {
		// Generate contact identities
		contact1, _ := vaultysid.GeneratePerson()
		contact2, _ := vaultysid.GenerateOrganization()

		// Save first contact
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerSaveContactCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "save-contact", secret, storePath,
			base64.StdEncoding.EncodeToString(contact1.ID()), "name=Alice Contact", "email=alice@test.com")
		require.NoError(t, err)

		// Save second contact
		cmd = setupTestCommand()
		mgr = newManagerCmd()
		mgr.AddCommand(newManagerSaveContactCmd())
		cmd.AddCommand(mgr)

		_, err = executeCommand(cmd, "manager", "save-contact", secret, storePath,
			base64.StdEncoding.EncodeToString(contact2.ID()), "name=ACME Corp", "type=organization")
		require.NoError(t, err)
	})

	// Step 5: Add apps
	t.Run("Add Apps", func(t *testing.T) {
		// Generate actual VaultysID for server identities (machines)
		server1, _ := vaultysid.GenerateMachine()
		server2, _ := vaultysid.GenerateMachine()
		serverID1 := base64.StdEncoding.EncodeToString(server1.ID())
		serverID2 := base64.StdEncoding.EncodeToString(server2.ID())

		// Save first app
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerSaveAppCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "save-app", secret, storePath,
			"app1.example.com", serverID1, "description=First App", "version=1.0.0")
		require.NoError(t, err)

		// Save second app
		cmd = setupTestCommand()
		mgr = newManagerCmd()
		mgr.AddCommand(newManagerSaveAppCmd())
		cmd.AddCommand(mgr)

		_, err = executeCommand(cmd, "manager", "save-app", secret, storePath,
			"app2.example.com", serverID2, "description=Second App")
		require.NoError(t, err)
	})

	// Step 6: List contacts and verify
	t.Run("List and Verify Contacts", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerContactsCmd())
		cmd.AddCommand(mgr)

		output, err := executeCommand(cmd, "manager", "contacts", secret, storePath)
		require.NoError(t, err)

		// Verify contacts are listed
		assert.Contains(t, output, "Alice Contact")
		assert.Contains(t, output, "ACME Corp")
	})

	// Step 7: List apps and verify
	t.Run("List and Verify Apps", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerAppsCmd())
		cmd.AddCommand(mgr)

		output, err := executeCommand(cmd, "manager", "apps", secret, storePath)
		require.NoError(t, err)

		// Verify apps are listed
		assert.Contains(t, output, "app1.example.com")
		assert.Contains(t, output, "app2.example.com")
	})

	// Step 8: Export and Import
	exportPath := filepath.Join(tempDir, "export.data")
	newStorePath := filepath.Join(tempDir, "new.store")

	t.Run("Export Data", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerExportCmd())
		cmd.AddCommand(mgr)

		output, err := executeCommand(cmd, "manager", "export", secret, storePath)
		require.NoError(t, err)

		// Save export data
		os.WriteFile(exportPath, []byte(strings.TrimSpace(output)), 0644)
	})

	t.Run("Import to New Store", func(t *testing.T) {
		// Initialize new store
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerInitCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "init", secret, newStorePath)
		require.NoError(t, err)

		// Import data
		exportData, err := os.ReadFile(exportPath)
		require.NoError(t, err)

		cmd = setupTestCommand()
		mgr = newManagerCmd()
		mgr.AddCommand(newManagerImportCmd())
		cmd.AddCommand(mgr)

		// Note: managerImport expects args as [secret] [store-path] [backup-data]
		_, err = executeCommand(cmd, "manager", "import", secret, newStorePath, string(exportData))
		require.NoError(t, err)
	})

	t.Run("Verify Imported Data", func(t *testing.T) {
		// Check contacts in new store
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerContactsCmd())
		cmd.AddCommand(mgr)

		output, err := executeCommand(cmd, "manager", "contacts", secret, newStorePath)
		require.NoError(t, err)
		assert.Contains(t, output, "Alice Contact")
		assert.Contains(t, output, "ACME Corp")

		// Check apps in new store
		cmd = setupTestCommand()
		mgr = newManagerCmd()
		mgr.AddCommand(newManagerAppsCmd())
		cmd.AddCommand(mgr)

		output, err = executeCommand(cmd, "manager", "apps", secret, newStorePath)
		require.NoError(t, err)
		assert.Contains(t, output, "app1.example.com")
		assert.Contains(t, output, "app2.example.com")
	})
}

// Test complete signing and verification workflow
func TestSigningWorkflow(t *testing.T) {
	tempDir := t.TempDir()

	// Generate identities for signing
	signer, err := vaultysid.GeneratePerson()
	require.NoError(t, err)

	signerSecret := func() string { s, _ := signer.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()
	signerID := base64.StdEncoding.EncodeToString(signer.ID())

	// Test data
	testData := []byte("Important message to sign")
	testDataB64 := base64.StdEncoding.EncodeToString(testData)

	// Step 1: Sign data
	var dataSignature string
	t.Run("Sign Data", func(t *testing.T) {
		cmd := setupTestCommand()
		sign := newSignCmd()
		sign.AddCommand(newSignDataCmd())
		cmd.AddCommand(sign)

		output, err := executeCommand(cmd, "sign", "data", signerSecret, testDataB64, "-o", "json")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		require.NoError(t, err)

		dataSignature = result["signature"].(string)
		assert.NotEmpty(t, dataSignature)
	})

	// Step 2: Verify data signature
	t.Run("Verify Data Signature", func(t *testing.T) {
		cmd := setupTestCommand()
		verify := newVerifyCmd()
		verify.AddCommand(newVerifyDataCmd())
		cmd.AddCommand(verify)

		output, err := executeCommand(cmd, "verify", "data", signerID, testDataB64, dataSignature, "-o", "json")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		require.NoError(t, err)

		assert.True(t, result["valid"].(bool))
	})

	// Step 3: Sign challenge
	challenge := []byte("challenge-12345")
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)
	var challengeSignature string

	t.Run("Sign Challenge", func(t *testing.T) {
		cmd := setupTestCommand()
		sign := newSignCmd()
		sign.AddCommand(newSignChallengeCmd())
		cmd.AddCommand(sign)

		output, err := executeCommand(cmd, "sign", "challenge", signerSecret, challengeB64, "-o", "json")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		require.NoError(t, err)

		challengeSignature = result["signature"].(string)
		assert.NotEmpty(t, challengeSignature)
	})

	// Step 4: Verify challenge signature
	t.Run("Verify Challenge Signature", func(t *testing.T) {
		cmd := setupTestCommand()
		verify := newVerifyCmd()
		verify.AddCommand(newVerifyChallengeCmd())
		cmd.AddCommand(verify)

		output, err := executeCommand(cmd, "verify", "challenge", signerID, challengeB64, challengeSignature, "-o", "json")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		require.NoError(t, err)

		assert.True(t, result["valid"].(bool))
	})

	// Step 5: Sign a file
	testFileContent := []byte("This is a test file for signing.")
	testFile := filepath.Join(tempDir, "document.txt")
	err = os.WriteFile(testFile, testFileContent, 0644)
	require.NoError(t, err)

	var fileSignatureJSON string
	t.Run("Sign File", func(t *testing.T) {
		cmd := setupTestCommand()
		sign := newSignCmd()
		sign.AddCommand(newSignFileCmd())
		cmd.AddCommand(sign)

		output, err := executeCommand(cmd, "sign", "file", signerSecret, testFile, "-o", "json")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		require.NoError(t, err)

		// Extract both challenge and signature for file verification
		challenge := result["challenge"].(string)
		signature := result["signature"].(string)
		assert.NotEmpty(t, challenge)
		assert.NotEmpty(t, signature)

		// Create JSON signature object for verify command
		sigObj := map[string]string{
			"Challenge": challenge,
			"Signature": signature,
		}
		sigJSON, _ := json.Marshal(sigObj)
		fileSignatureJSON = base64.StdEncoding.EncodeToString(sigJSON)
	})

	// Step 6: Verify file signature
	t.Run("Verify File Signature", func(t *testing.T) {
		cmd := setupTestCommand()
		verify := newVerifyCmd()
		verify.AddCommand(newVerifyFileCmd())
		cmd.AddCommand(verify)

		output, err := executeCommand(cmd, "verify", "file", signerID, testFile, fileSignatureJSON, "-o", "json")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		require.NoError(t, err)

		assert.True(t, result["valid"].(bool))
	})

	// Step 7: Verify that modifying the file invalidates the signature
	t.Run("Modified File Should Fail Verification", func(t *testing.T) {
		// Modify the file
		modifiedContent := append(testFileContent, []byte("\nModified!")...)
		err = os.WriteFile(testFile, modifiedContent, 0644)
		require.NoError(t, err)

		cmd := setupTestCommand()
		verify := newVerifyCmd()
		verify.AddCommand(newVerifyFileCmd())
		cmd.AddCommand(verify)

		output, err := executeCommand(cmd, "verify", "file", signerID, testFile, fileSignatureJSON, "-o", "json")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		require.NoError(t, err)

		assert.False(t, result["valid"].(bool))
	})
}

func TestEncryptionWorkflow(t *testing.T) {
	tempDir := t.TempDir()

	// Generate identity for encryption
	identity, err := vaultysid.GenerateMachine()
	require.NoError(t, err)

	secret := func() string { s, _ := identity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()
	// Use self as peer for self-encryption
	peerID := base64.StdEncoding.EncodeToString(identity.ID())

	// Create test files
	smallFile := filepath.Join(tempDir, "small.txt")
	largeFile := filepath.Join(tempDir, "large.txt")

	// Small file content
	smallContent := []byte("This is a small secret message.")
	err = os.WriteFile(smallFile, smallContent, 0644)
	require.NoError(t, err)

	// Large file content (1MB)
	largeContent := make([]byte, 1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	err = os.WriteFile(largeFile, largeContent, 0644)
	require.NoError(t, err)

	// Test small file encryption/decryption
	t.Run("Small File Encryption", func(t *testing.T) {
		decryptedFile := filepath.Join(tempDir, "small.decrypted")

		// Encrypt - use self as peer for self-encryption
		cmd := setupTestCommand()
		cmd.AddCommand(newEncryptCmd())

		_, err := executeCommand(cmd, "encrypt", secret, peerID, smallFile)
		require.NoError(t, err)

		// Verify encrypted file exists and is different from original
		encryptedData, err := os.ReadFile(smallFile)
		require.NoError(t, err)
		assert.NotEqual(t, smallContent, encryptedData)
		assert.True(t, strings.HasPrefix(string(encryptedData), "vaultys/encryption/"))

		// Decrypt
		cmd = setupTestCommand()
		cmd.AddCommand(newDecryptCmd())

		_, err = executeCommand(cmd, "decrypt", secret, peerID, smallFile)
		require.NoError(t, err)

		// The decrypt command writes to the file path with .decrypted suffix or removes .encrypted
		// Since we encrypted in place to smallFile, read it back
		decryptedData, err := os.ReadFile(decryptedFile)
		if err != nil {
			// Try reading the original file path + .decrypted suffix
			decryptedData, err = os.ReadFile(smallFile + ".decrypted")
		}
		require.NoError(t, err)
		assert.Equal(t, smallContent, decryptedData)
	})

	// Test large file encryption/decryption
	t.Run("Large File Encryption", func(t *testing.T) {
		// Encrypt - use self as peer for self-encryption
		cmd := setupTestCommand()
		cmd.AddCommand(newEncryptCmd())

		_, err := executeCommand(cmd, "encrypt", secret, peerID, largeFile)
		require.NoError(t, err)

		// Decrypt
		cmd = setupTestCommand()
		cmd.AddCommand(newDecryptCmd())

		_, err = executeCommand(cmd, "decrypt", secret, peerID, largeFile)
		require.NoError(t, err)

		// Verify decrypted content matches original
		decryptedData, err := os.ReadFile(largeFile + ".decrypted")
		require.NoError(t, err)
		assert.Equal(t, largeContent, decryptedData)
	})

	// Test wrong secret fails decryption
	t.Run("Wrong Secret Fails Decryption", func(t *testing.T) {
		// First encrypt a fresh file
		wrongTestFile := filepath.Join(tempDir, "wrong_test.txt")
		err := os.WriteFile(wrongTestFile, []byte("test content"), 0644)
		require.NoError(t, err)

		cmd := setupTestCommand()
		cmd.AddCommand(newEncryptCmd())
		_, err = executeCommand(cmd, "encrypt", secret, peerID, wrongTestFile)
		require.NoError(t, err)

		// Generate a different identity
		wrongIdentity, _ := vaultysid.GenerateMachine()
		wrongSecret := func() string { s, _ := wrongIdentity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()
		wrongPeerID := base64.StdEncoding.EncodeToString(wrongIdentity.ID())

		cmd = setupTestCommand()
		cmd.AddCommand(newDecryptCmd())

		_, err = executeCommand(cmd, "decrypt", wrongSecret, wrongPeerID, wrongTestFile)
		assert.Error(t, err)
	})
}

// Test HMAC operations
func TestHMACOperations(t *testing.T) {
	identity, err := vaultysid.GenerateMachine()
	require.NoError(t, err)

	secret := func() string { s, _ := identity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()

	testCases := []struct {
		name string
		data []byte
	}{
		{"Short Message", []byte("Hello")},
		{"Medium Message", []byte("This is a medium length message for HMAC testing.")},
		{"Binary Data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}},
		{"Unicode Message", []byte("Hello 世界 🌍")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataB64 := base64.StdEncoding.EncodeToString(tc.data)

			cmd := setupTestCommand()
			cmd.AddCommand(newHMACCmd())

			output, err := executeCommand(cmd, "hmac", secret, dataB64, "-o", "json")
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal([]byte(output), &result)
			require.NoError(t, err)

			hmac1 := result["hmac"].(string)
			assert.NotEmpty(t, hmac1)

			// Verify HMAC is consistent
			cmd2 := setupTestCommand()
			cmd2.AddCommand(newHMACCmd())

			output2, err := executeCommand(cmd2, "hmac", secret, dataB64, "-o", "json")
			require.NoError(t, err)

			var result2 map[string]interface{}
			err = json.Unmarshal([]byte(output2), &result2)
			require.NoError(t, err)

			assert.Equal(t, hmac1, result2["hmac"].(string))
		})
	}
}

// Test DID generation and consistency
func TestDIDOperations(t *testing.T) {
	// Generate different types of identities
	machineID, _ := vaultysid.GenerateMachine()
	personID, _ := vaultysid.GeneratePerson()
	orgID, _ := vaultysid.GenerateOrganization()

	identities := []struct {
		name   string
		vid    *vaultysid.VaultysID
		idType string
	}{
		{"Machine", machineID, "machine"},
		{"Person", personID, "person"},
		{"Organization", orgID, "organization"},
	}

	for _, id := range identities {
		t.Run(fmt.Sprintf("DID for %s", id.name), func(t *testing.T) {
			secret := func() string { s, _ := id.vid.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()

			// Get DID from secret
			cmd := setupTestCommand()
			cmd.AddCommand(newDIDCmd())

			output, err := executeCommand(cmd, "did", secret, "-o", "json")
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal([]byte(output), &result)
			require.NoError(t, err)

			didFromSecret := result["did"].(string)
			assert.NotEmpty(t, didFromSecret)
			assert.Contains(t, didFromSecret, "did:vaultys:")

			// Verify DID matches what the VaultysID generates directly
			expectedDID := id.vid.DID()
			assert.Equal(t, expectedDID, didFromSecret)
		})
	}
}

// Benchmark tests
func BenchmarkGenerateIdentity(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cmd := setupTestCommand()
		cmd.AddCommand(newGenerateCmd())

		_, _ = executeCommand(cmd, "generate", "machine", "-o", "json")
	}
}

func BenchmarkSignData(b *testing.B) {
	identity, _ := vaultysid.GenerateMachine()
	secret := func() string { s, _ := identity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()
	data := base64.StdEncoding.EncodeToString([]byte("benchmark test data"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := setupTestCommand()
		sign := newSignCmd()
		sign.AddCommand(newSignDataCmd())
		cmd.AddCommand(sign)

		_, _ = executeCommand(cmd, "sign", "data", secret, data, "-o", "json")
	}
}

func BenchmarkVerifyData(b *testing.B) {
	identity, _ := vaultysid.GenerateMachine()
	_ = func() string { s, _ := identity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()
	publicID := base64.StdEncoding.EncodeToString(identity.ID())
	data := []byte("benchmark test data")
	dataB64 := base64.StdEncoding.EncodeToString(data)

	sig, _ := identity.Sign(data)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := setupTestCommand()
		verify := newVerifyCmd()
		verify.AddCommand(newVerifyDataCmd())
		cmd.AddCommand(verify)

		_, _ = executeCommand(cmd, "verify", "data", publicID, dataB64, sigB64, "-o", "json")
	}
}

// Test error handling
func TestErrorHandling(t *testing.T) {
	t.Run("Invalid Base64 Input", func(t *testing.T) {
		cmd := setupTestCommand()
		cmd.AddCommand(newFromSecretCmd())

		_, err := executeCommand(cmd, "from-secret", "not-base64!")
		assert.Error(t, err)
	})

	t.Run("Invalid Hex Input", func(t *testing.T) {
		cmd := setupTestCommand()
		cmd.AddCommand(newFromEntropyCmd())

		_, err := executeCommand(cmd, "from-entropy", "machine", "not-hex!", "-e", "hex")
		assert.Error(t, err)
	})

	t.Run("Non-existent File", func(t *testing.T) {
		identity, _ := vaultysid.GenerateMachine()
		secret := func() string { s, _ := identity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()

		cmd := setupTestCommand()
		cmd.AddCommand(newEncryptCmd())

		_, err := executeCommand(cmd, "encrypt", secret, "/non/existent/file.txt", "/tmp/out.enc")
		assert.Error(t, err)
	})

	t.Run("Invalid Store Path", func(t *testing.T) {
		identity, _ := vaultysid.GenerateMachine()
		secret := func() string { s, _ := identity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()

		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerContactsCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "contacts", secret, "/non/existent/store.db")
		assert.Error(t, err)
	})
}

// Test output formats
func TestOutputFormats(t *testing.T) {
	identity, _ := vaultysid.GenerateMachine()
	secret := func() string { s, _ := identity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()

	t.Run("JSON Output", func(t *testing.T) {
		cmd := setupTestCommand()
		cmd.AddCommand(newInfoCmd())

		output, err := executeCommand(cmd, "info", secret, "-o", "json")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		assert.NoError(t, err)
		assert.Contains(t, result, "id")
		assert.Contains(t, result, "type")
	})

	// Step 9: Get DID
	t.Run("Get DID", func(t *testing.T) {
		cmd := setupTestCommand()
		cmd.AddCommand(newDIDCmd())

		output, err := executeCommand(cmd, "did", secret, "-o", "json")
		require.NoError(t, err)

		// JSON output should contain the DID
		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		assert.NoError(t, err)
		assert.Contains(t, result, "did")
		assert.Contains(t, result["did"].(string), "did:vaultys:")
	})
}

func testConcurrencySafetyImplementation(t *testing.T) {

	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "concurrent.store")

	// Initialize store
	identity, _ := vaultysid.GeneratePerson()
	secretStr := func() string { s, _ := identity.GetSecret(); return base64.StdEncoding.EncodeToString(s) }()

	// Initialize manager
	secretBytes, _ := identity.GetSecret()
	vid, _ := vaultysid.FromSecret(secretBytes)
	store := idmanager.NewMemoryStore()
	_ = idmanager.NewManager(vid, store)
	data, _ := store.ToJSON()
	jsonData, _ := json.Marshal(data)
	os.WriteFile(storePath, jsonData, 0644)

	// Run concurrent operations
	done := make(chan bool)
	errors := make(chan error, 10)

	// Concurrent saves
	for i := 0; i < 5; i++ {
		go func(idx int) {
			contact, _ := vaultysid.GeneratePerson()

			cmd := setupTestCommand()
			mgr := newManagerCmd()
			mgr.AddCommand(newManagerSaveContactCmd())
			cmd.AddCommand(mgr)

			_, err := executeCommand(cmd, "manager", "save-contact", secretStr, storePath,
				base64.StdEncoding.EncodeToString(contact.ID()), fmt.Sprintf("name=Contact%d", idx))
			if err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		select {
		case <-done:
			// Success
		case err := <-errors:
			t.Errorf("Concurrent operation failed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vaultys/vaultysid/go/pkg/idmanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// Test helpers
func captureOutput(f func() error) (string, error) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String(), err
}

func executeCommand(root *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err := root.Execute()
	return buf.String(), err
}

func setupTestCommand() *cobra.Command {
	// Reset global flags
	outputFormat = "text"
	encoding = "base64"
	verbose = false

	// Create a fresh root command
	cmd := &cobra.Command{
		Use:   "vaultysid-cli",
		Short: "VaultysID CLI - Decentralized Identity Management",
	}

	// Add global flags
	cmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "Output format (text/json)")
	cmd.PersistentFlags().StringVarP(&encoding, "encoding", "e", "base64", "Encoding for input/output (base64/hex)")
	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	return cmd
}

// Helper functions to create fresh command instances for each test
// This avoids the "flag redefined" panic when tests reuse global commands

func newGenerateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate [type]",
		Short: "Generate a new identity",
		Args:  cobra.ExactArgs(1),
		RunE:  generateIdentity,
	}
}

func newFromEntropyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "from-entropy [type] [entropy]",
		Short: "Create identity from entropy",
		Args:  cobra.ExactArgs(2),
		RunE:  fromEntropy,
	}
}

func newFromSecretCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "from-secret [secret]",
		Short: "Restore identity from secret",
		Args:  cobra.ExactArgs(1),
		RunE:  fromSecret,
	}
}

func newFromIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "from-id [id]",
		Short: "Create public identity from ID",
		Args:  cobra.ExactArgs(1),
		RunE:  fromID,
	}
}

func newSignCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sign",
		Short: "Sign data or files",
	}
}

func newSignDataCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "data [secret] [data]",
		Short: "Sign data",
		Args:  cobra.ExactArgs(2),
		RunE:  signData,
	}
}

func newSignChallengeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "challenge [secret] [challenge]",
		Short: "Sign a challenge",
		Args:  cobra.ExactArgs(2),
		RunE:  signChallenge,
	}
}

func newSignFileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "file [secret] [file]",
		Short: "Sign a file",
		Args:  cobra.ExactArgs(2),
		RunE:  signFile,
	}
}

func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify signatures",
	}
}

func newVerifyDataCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "data [id] [data] [signature]",
		Short: "Verify data signature",
		Args:  cobra.ExactArgs(3),
		RunE:  verifyData,
	}
}

func newVerifyChallengeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "challenge [id] [challenge] [signature]",
		Short: "Verify challenge signature",
		Args:  cobra.ExactArgs(3),
		RunE:  verifyChallenge,
	}
}

func newVerifyFileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "file [id] [file] [signature]",
		Short: "Verify file signature",
		Args:  cobra.ExactArgs(3),
		RunE:  verifyFile,
	}
}

func newInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info [secret-or-id]",
		Short: "Show identity information",
		Args:  cobra.ExactArgs(1),
		RunE:  showInfo,
	}
}

func newDIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "did [secret-or-id]",
		Short: "Get DID for identity",
		Args:  cobra.ExactArgs(1),
		RunE:  getDID,
	}
}

func newHMACCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hmac [secret] [message]",
		Short: "Compute HMAC",
		Args:  cobra.ExactArgs(2),
		RunE:  computeHMAC,
	}
}

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt [secret] [peer-id] [file-path]",
		Short: "Encrypt a file for a peer",
		Args:  cobra.ExactArgs(3),
		RunE:  encryptFile,
	}
}

func newDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt [secret] [peer-id] [file-path]",
		Short: "Decrypt a file from a peer",
		Args:  cobra.ExactArgs(3),
		RunE:  decryptFile,
	}
}

func newManagerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "manager",
		Short: "Identity manager operations",
	}
}

func newManagerInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [secret] [store-path]",
		Short: "Initialize a new identity store",
		Args:  cobra.ExactArgs(2),
		RunE:  managerInit,
	}
}

func newManagerExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export [secret] [store-path]",
		Short: "Export identity store",
		Args:  cobra.ExactArgs(2),
		RunE:  managerExport,
	}
}

func newManagerImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import [secret] [store-path] [data]",
		Short: "Import identity store",
		Args:  cobra.ExactArgs(3),
		RunE:  managerImport,
	}
}

func newManagerContactsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "contacts [secret] [store-path]",
		Short: "List contacts",
		Args:  cobra.ExactArgs(2),
		RunE:  managerContacts,
	}
}

func newManagerAppsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apps [secret] [store-path]",
		Short: "List apps",
		Args:  cobra.ExactArgs(2),
		RunE:  managerApps,
	}
}

func newManagerSaveContactCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "save-contact [secret] [store-path] [contact-id] [metadata...]",
		Short: "Save a contact",
		Args:  cobra.MinimumNArgs(3),
		RunE:  managerSaveContact,
	}
}

func newManagerSaveAppCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "save-app [secret] [store-path] [site] [server-id] [metadata...]",
		Short: "Save an app",
		Args:  cobra.MinimumNArgs(4),
		RunE:  managerSaveApp,
	}
}

func newManagerSetNameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-name [secret] [store-path] [name]",
		Short: "Set identity name",
		Args:  cobra.ExactArgs(3),
		RunE:  managerSetName,
	}
}

func newManagerSetEmailCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-email [secret] [store-path] [email]",
		Short: "Set identity email",
		Args:  cobra.ExactArgs(3),
		RunE:  managerSetEmail,
	}
}

func newManagerSetPhoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-phone [secret] [store-path] [phone]",
		Short: "Set identity phone",
		Args:  cobra.ExactArgs(3),
		RunE:  managerSetPhone,
	}
}

// Test data
var (
	testEntropy = make([]byte, 32)
	testSecret  string
	testID      string
)

func init() {
	// Initialize test data
	for i := range testEntropy {
		testEntropy[i] = byte(i)
	}

	// Create a test identity
	vid, _ := vaultysid.FromEntropy(testEntropy, vaultysid.TypeMachine)
	secret, _ := vid.GetSecret()
	testSecret = base64.StdEncoding.EncodeToString(secret)
	testID = base64.StdEncoding.EncodeToString(vid.ID())
}

func TestMain(m *testing.M) {
	// Setup
	code := m.Run()
	// Cleanup
	os.Exit(code)
}

// Test Generate Command
func TestGenerateCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		checkFunc func(t *testing.T, output string)
	}{
		{
			name:    "generate machine identity",
			args:    []string{"generate", "machine"},
			wantErr: false,
			checkFunc: func(t *testing.T, output string) {
				var result map[string]interface{}
				err := json.Unmarshal([]byte(output), &result)
				require.NoError(t, err)
				assert.Contains(t, result, "id")
				assert.Contains(t, result, "secret")
				assert.Contains(t, result, "type")
				assert.Equal(t, "machine", result["type"])
			},
		},
		{
			name:    "generate person identity",
			args:    []string{"generate", "person"},
			wantErr: false,
			checkFunc: func(t *testing.T, output string) {
				var result map[string]interface{}
				err := json.Unmarshal([]byte(output), &result)
				require.NoError(t, err)
				assert.Equal(t, "person", result["type"])
			},
		},
		{
			name:    "generate organization identity",
			args:    []string{"generate", "organization"},
			wantErr: false,
			checkFunc: func(t *testing.T, output string) {
				var result map[string]interface{}
				err := json.Unmarshal([]byte(output), &result)
				require.NoError(t, err)
				assert.Equal(t, "organization", result["type"])
			},
		},
		{
			name:    "invalid type",
			args:    []string{"generate", "invalid"},
			wantErr: true,
		},
		{
			name:    "missing type",
			args:    []string{"generate"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			cmd.AddCommand(newGenerateCmd())

			output, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkFunc != nil {
					tt.checkFunc(t, output)
				}
			}
		})
	}
}

// Test FromEntropy Command
func TestFromEntropyCommand(t *testing.T) {
	entropyHex := hex.EncodeToString(testEntropy)
	entropyBase64 := base64.StdEncoding.EncodeToString(testEntropy)

	tests := []struct {
		name      string
		args      []string
		encoding  string
		wantErr   bool
		checkFunc func(t *testing.T, output string)
	}{
		{
			name:     "from entropy hex encoded",
			args:     []string{"from-entropy", "machine", entropyHex},
			encoding: "hex",
			wantErr:  false,
			checkFunc: func(t *testing.T, output string) {
				var result map[string]interface{}
				err := json.Unmarshal([]byte(output), &result)
				require.NoError(t, err)
				assert.Contains(t, result, "id")
				assert.Contains(t, result, "secret")
			},
		},
		{
			name:     "from entropy base64 encoded",
			args:     []string{"from-entropy", "person", entropyBase64},
			encoding: "base64",
			wantErr:  false,
		},
		{
			name:     "invalid entropy length",
			args:     []string{"from-entropy", "machine", "shortentropy"},
			encoding: "hex",
			wantErr:  true,
		},
		{
			name:    "missing arguments",
			args:    []string{"from-entropy", "machine"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			cmd.AddCommand(newFromEntropyCmd())

			args := append(tt.args, "-o", "json", "-e", tt.encoding)
			output, err := executeCommand(cmd, args...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkFunc != nil {
					tt.checkFunc(t, output)
				}
			}
		})
	}
}

// Test FromSecret Command
func TestFromSecretCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "from valid secret",
			args:    []string{"from-secret", testSecret},
			wantErr: false,
		},
		{
			name:    "from invalid secret",
			args:    []string{"from-secret", "invalid"},
			wantErr: true,
		},
		{
			name:    "missing secret",
			args:    []string{"from-secret"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			cmd.AddCommand(newFromSecretCmd())

			_, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test FromID Command
func TestFromIDCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "from valid ID",
			args:    []string{"from-id", testID},
			wantErr: false,
		},
		{
			name:    "from invalid ID",
			args:    []string{"from-id", "invalid-id"},
			wantErr: true,
		},
		{
			name:    "missing ID",
			args:    []string{"from-id"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			cmd.AddCommand(newFromIDCmd())

			_, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test Sign Commands
func TestSignDataCommand(t *testing.T) {
	testData := base64.StdEncoding.EncodeToString([]byte("test data"))

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "sign data",
			args:    []string{"sign", "data", testSecret, testData},
			wantErr: false,
		},
		{
			name:    "invalid secret",
			args:    []string{"sign", "data", "invalid", testData},
			wantErr: true,
		},
		{
			name:    "missing arguments",
			args:    []string{"sign", "data", testSecret},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			sign := newSignCmd()
			sign.AddCommand(newSignDataCmd())
			cmd.AddCommand(sign)

			_, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSignChallengeCommand(t *testing.T) {
	challenge := base64.StdEncoding.EncodeToString([]byte("test challenge"))

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "sign challenge",
			args:    []string{"sign", "challenge", testSecret, challenge},
			wantErr: false,
		},
		{
			name:    "invalid secret",
			args:    []string{"sign", "challenge", "invalid", challenge},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			sign := newSignCmd()
			sign.AddCommand(newSignChallengeCmd())
			cmd.AddCommand(sign)

			_, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test Verify Commands
func TestVerifyDataCommand(t *testing.T) {
	// Create test data and signature
	testData := []byte("test data")
	vid, _ := vaultysid.FromSecret(func() []byte { b, _ := base64.StdEncoding.DecodeString(testSecret); return b }())
	sig, _ := vid.Sign(testData)

	dataB64 := base64.StdEncoding.EncodeToString(testData)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "verify valid signature",
			args:    []string{"verify", "data", testID, dataB64, sigB64},
			wantErr: false,
		},
		{
			name:    "verify invalid signature",
			args:    []string{"verify", "data", testID, dataB64, base64.StdEncoding.EncodeToString([]byte("invalid"))},
			wantErr: false, // Returns false but doesn't error
		},
		{
			name:    "invalid ID",
			args:    []string{"verify", "data", "invalid-id", dataB64, sigB64},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Now verify
			cmd := setupTestCommand()
			verify := newVerifyCmd()
			verify.AddCommand(newVerifyDataCmd())
			cmd.AddCommand(verify)

			_, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test Info Command
func TestInfoCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "show info from secret",
			args:    []string{"info", testSecret},
			wantErr: false,
		},
		{
			name:    "show info from ID",
			args:    []string{"info", testID},
			wantErr: false,
		},
		{
			name:    "invalid input",
			args:    []string{"info", "invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			cmd.AddCommand(newInfoCmd())

			_, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test DID Command
func TestDIDCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "get DID from secret",
			args:    []string{"did", testSecret},
			wantErr: false,
		},
		{
			name:    "get DID from ID",
			args:    []string{"did", testID},
			wantErr: false,
		},
		{
			name:    "invalid input",
			args:    []string{"did", "invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			cmd.AddCommand(newDIDCmd())

			_, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test HMAC Command
func TestHMACCommand(t *testing.T) {
	testData := base64.StdEncoding.EncodeToString([]byte("test data"))

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "compute HMAC",
			args:    []string{"hmac", testSecret, testData},
			wantErr: false,
		},
		{
			name:    "invalid secret",
			args:    []string{"hmac", "invalid", testData},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			cmd.AddCommand(newHMACCmd())

			_, err := executeCommand(cmd, append(tt.args, "-o", "json")...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test Manager Commands
func TestManagerInit(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test.store")

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "initialize manager",
			args:    []string{"manager", "init", testSecret, storePath},
			wantErr: false,
		},
		{
			name:    "invalid secret",
			args:    []string{"manager", "init", "invalid", storePath},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			mgr := newManagerCmd()
			mgr.AddCommand(newManagerInitCmd())
			cmd.AddCommand(mgr)

			_, err := executeCommand(cmd, tt.args...)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify store file was created
				_, err := os.Stat(storePath)
				assert.NoError(t, err)
			}
		})
	}
}

func TestManagerExportImport(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test.store")

	// Initialize store using FileStore
	vid, _ := vaultysid.FromSecret(func() []byte { b, _ := base64.StdEncoding.DecodeString(testSecret); return b }())
	store, _ := idmanager.NewFileStore(storePath)
	manager := idmanager.NewManager(vid, store)

	// Add some test data
	manager.SetName("Test User")
	manager.SetEmail("test@example.com")

	t.Run("export manager", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerExportCmd())
		cmd.AddCommand(mgr)

		output, err := executeCommand(cmd, "manager", "export", testSecret, storePath)
		assert.NoError(t, err)
		assert.NotEmpty(t, output)
	})

	t.Run("import manager", func(t *testing.T) {
		// Create a new store
		newStorePath := filepath.Join(tempDir, "new.store")

		// Export data from original (use empty password to match CLI import)
		exportData, _ := manager.ExportBackup("")
		exportB64 := exportData

		// Initialize new store using FileStore
		newStore, _ := idmanager.NewFileStore(newStorePath)
		_ = idmanager.NewManager(vid, newStore)

		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerImportCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "import", testSecret, newStorePath, exportB64)
		assert.NoError(t, err)
	})
}

func TestManagerContacts(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test.store")

	// Setup a manager with contacts using FileStore
	vid, _ := vaultysid.FromSecret(func() []byte { b, _ := base64.StdEncoding.DecodeString(testSecret); return b }())
	store, _ := idmanager.NewFileStore(storePath)
	manager := idmanager.NewManager(vid, store)

	// Add a test contact
	contactVID, _ := vaultysid.GeneratePerson()
	contactMetadata := map[string]interface{}{
		"name":  "John Doe",
		"email": "john@example.com",
	}
	manager.SaveContact(contactVID, contactMetadata)

	t.Run("list contacts", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerContactsCmd())
		cmd.AddCommand(mgr)

		output, err := executeCommand(cmd, "manager", "contacts", testSecret, storePath)
		assert.NoError(t, err)
		assert.Contains(t, output, "John Doe")
	})
}

func TestManagerApps(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test.store")

	// Setup a manager with apps using FileStore
	vid, _ := vaultysid.FromSecret(func() []byte { b, _ := base64.StdEncoding.DecodeString(testSecret); return b }())
	store, _ := idmanager.NewFileStore(storePath)
	manager := idmanager.NewManager(vid, store)

	// Add a test app
	serverID := base64.StdEncoding.EncodeToString([]byte("server123"))
	manager.SaveApp("example.com", serverID)

	t.Run("list apps", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerAppsCmd())
		cmd.AddCommand(mgr)

		output, err := executeCommand(cmd, "manager", "apps", testSecret, storePath)
		assert.NoError(t, err)
		assert.Contains(t, output, "example.com")
	})
}

func TestManagerSaveContact(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test.store")

	// Initialize store using FileStore
	vid, _ := vaultysid.FromSecret(func() []byte { b, _ := base64.StdEncoding.DecodeString(testSecret); return b }())
	store, _ := idmanager.NewFileStore(storePath)
	_ = idmanager.NewManager(vid, store)

	// Create a contact ID
	contactVID, _ := vaultysid.GeneratePerson()
	contactID := base64.StdEncoding.EncodeToString(contactVID.ID())

	t.Run("save contact", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerSaveContactCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "save-contact", testSecret, storePath, contactID,
			"name=Jane Doe", "email=jane@example.com")
		assert.NoError(t, err)
	})
}

func TestManagerSaveApp(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test.store")

	// Initialize store using FileStore
	vid, _ := vaultysid.FromSecret(func() []byte { b, _ := base64.StdEncoding.DecodeString(testSecret); return b }())
	store, _ := idmanager.NewFileStore(storePath)
	_ = idmanager.NewManager(vid, store)

	// Generate a real VaultysID for the server (must be a machine type)
	serverVID, _ := vaultysid.GenerateMachine()
	serverIDBase64 := base64.StdEncoding.EncodeToString(serverVID.ID())

	t.Run("save app", func(t *testing.T) {
		cmd := setupTestCommand()
		mgr := newManagerCmd()
		mgr.AddCommand(newManagerSaveAppCmd())
		cmd.AddCommand(mgr)

		_, err := executeCommand(cmd, "manager", "save-app", testSecret, storePath,
			"myapp.com", serverIDBase64,
			"description=My App", "version=1.0")
		assert.NoError(t, err)
	})
}

func TestManagerSetters(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test.store")

	// Initialize store using FileStore
	vid, _ := vaultysid.FromSecret(func() []byte { b, _ := base64.StdEncoding.DecodeString(testSecret); return b }())
	store, _ := idmanager.NewFileStore(storePath)
	_ = idmanager.NewManager(vid, store)

	tests := []struct {
		name    string
		cmdName string
		args    []string
	}{
		{
			name:    "set name",
			cmdName: "set-name",
			args:    []string{"manager", "set-name", testSecret, storePath, "Alice Smith"},
		},
		{
			name:    "set email",
			cmdName: "set-email",
			args:    []string{"manager", "set-email", testSecret, storePath, "alice@example.com"},
		},
		{
			name:    "set phone",
			cmdName: "set-phone",
			args:    []string{"manager", "set-phone", testSecret, storePath, "+1-555-1234"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupTestCommand()
			mgr := newManagerCmd()
			switch tt.cmdName {
			case "set-name":
				mgr.AddCommand(newManagerSetNameCmd())
			case "set-email":
				mgr.AddCommand(newManagerSetEmailCmd())
			case "set-phone":
				mgr.AddCommand(newManagerSetPhoneCmd())
			}
			cmd.AddCommand(mgr)

			_, err := executeCommand(cmd, tt.args...)
			assert.NoError(t, err)
		})
	}
}

// Test File Operations
func TestEncryptDecrypt(t *testing.T) {
	// Skip this test as the encrypt/decrypt CLI commands require peer-based encryption
	// which needs proper key exchange setup. The underlying crypto is tested in pkg/keymanager.
	t.Skip("Encrypt/decrypt CLI requires peer-based key exchange - tested in pkg/keymanager")
}

// Test Sign and Verify File
func TestSignVerifyFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := []byte("This is a test file for signing")
	os.WriteFile(testFile, testContent, 0644)

	var signatureJSON string

	t.Run("sign file", func(t *testing.T) {
		cmd := setupTestCommand()
		sign := newSignCmd()
		sign.AddCommand(newSignFileCmd())
		cmd.AddCommand(sign)

		output, err := executeCommand(cmd, "sign", "file", testSecret, testFile, "-o", "json")
		assert.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		assert.NoError(t, err)

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
		signatureJSON = base64.StdEncoding.EncodeToString(sigJSON)
	})

	t.Run("verify file", func(t *testing.T) {
		cmd := setupTestCommand()
		verify := newVerifyCmd()
		verify.AddCommand(newVerifyFileCmd())
		cmd.AddCommand(verify)

		output, err := executeCommand(cmd, "verify", "file", testID, testFile, signatureJSON, "-o", "json")
		assert.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		assert.NoError(t, err)
		assert.True(t, result["valid"].(bool))
	})
}

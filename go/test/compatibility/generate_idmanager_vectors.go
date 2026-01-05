//go:build ignore
// +build ignore

// Run this file with: go run generate_idmanager_vectors.go
// It generates comprehensive test vectors for IdManager TypeScript compatibility testing

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vaultys/vaultysid-go/pkg/crypto"
	"github.com/vaultys/vaultysid-go/pkg/idmanager"
	"github.com/vaultys/vaultysid-go/pkg/vaultysid"
)

type IdManagerTestVectors struct {
	Description   string                   `json:"description"`
	Timestamp     string                   `json:"timestamp"`
	Version       string                   `json:"version"`
	Identity      IdentityManagerVectors   `json:"identity"`
	Contacts      ContactManagementVectors `json:"contacts"`
	Apps          AppManagementVectors     `json:"apps"`
	Files         FileOperationVectors     `json:"files"`
	KeyDerivation KeyDerivationVectors     `json:"keyDerivation"`
	PRF           PRFVectors               `json:"prf"`
	Backup        BackupVectors            `json:"backup"`
	Challenge     ChallengeSigningVectors  `json:"challenge"`
	Storage       StorageVectors           `json:"storage"`
}

type IdentityManagerVectors struct {
	Entropy     string                 `json:"entropy"`
	Type        uint8                  `json:"type"`
	Name        string                 `json:"name"`
	Email       string                 `json:"email"`
	Phone       string                 `json:"phone"`
	DisplayName string                 `json:"displayName"`
	DID         string                 `json:"did"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type ContactManagementVectors struct {
	Contacts []ContactVector `json:"contacts"`
}

type ContactVector struct {
	Entropy     string                 `json:"entropy"`
	DID         string                 `json:"did"`
	IDBytes     string                 `json:"idBytes"`
	Certificate string                 `json:"certificate,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type AppManagementVectors struct {
	Apps []AppVector `json:"apps"`
}

type AppVector struct {
	Site        string `json:"site"`
	ServerID    string `json:"serverId"`
	Certificate string `json:"certificate,omitempty"`
	Timestamp   int64  `json:"timestamp"`
}

type FileOperationVectors struct {
	Signing    FileSigningVector    `json:"signing"`
	Encryption FileEncryptionVector `json:"encryption"`
}

type FileSigningVector struct {
	File      FileData      `json:"file"`
	Signature FileSignature `json:"signature"`
}

type FileEncryptionVector struct {
	Original  FileData `json:"original"`
	Password  string   `json:"password"`
	Encrypted FileData `json:"encrypted"`
}

type FileData struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	DataHex    string `json:"dataHex"`
	DataBase64 string `json:"dataBase64"`
}

type FileSignature struct {
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

type KeyDerivationVectors struct {
	Protocol   ProtocolKeyVector   `json:"protocol"`
	Service    ServiceKeyVector    `json:"service"`
	Encryption EncryptionKeyVector `json:"encryption"`
	Signing    SigningKeyVector    `json:"signing"`
	Session    SessionKeyVector    `json:"session"`
	Channel    ChannelKeyVector    `json:"channel"`
	HMAC       HMACKeyVector       `json:"hmac"`
}

type ProtocolKeyVector struct {
	Protocol  string `json:"protocol"`
	Version   int    `json:"version"`
	PublicKey string `json:"publicKey"`
}

type ServiceKeyVector struct {
	Service   string `json:"service"`
	Protocol  string `json:"protocol"`
	PublicKey string `json:"publicKey"`
}

type EncryptionKeyVector struct {
	RecipientDID string `json:"recipientDid"`
	Key          string `json:"key"`
}

type SigningKeyVector struct {
	Context string `json:"context"`
	Key     string `json:"key"`
}

type SessionKeyVector struct {
	SessionID string `json:"sessionId"`
	TTL       int64  `json:"ttl"`
	Key       string `json:"key"`
}

type ChannelKeyVector struct {
	PeerPublicKey string `json:"peerPublicKey"`
	Nonce         string `json:"nonce"`
	EncKey        string `json:"encKey"`
	MacKey        string `json:"macKey"`
}

type HMACKeyVector struct {
	Purpose string `json:"purpose"`
	Message string `json:"message"`
	Result  string `json:"result"`
}

type PRFVectors struct {
	AppID   string   `json:"appId"`
	Salts   []string `json:"salts"`
	Results []string `json:"results"`
}

type BackupVectors struct {
	Password        string                 `json:"password"`
	EncryptedBackup string                 `json:"encryptedBackup"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type ChallengeSigningVectors struct {
	ProtocolV0 ChallengeVector `json:"protocolV0"`
	ProtocolV1 ChallengeVector `json:"protocolV1"`
}

type ChallengeVector struct {
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
	Version   int    `json:"version"`
}

type StorageVectors struct {
	MemoryStore StorageTestVector `json:"memoryStore"`
	Substores   []SubstoreVector  `json:"substores"`
}

type StorageTestVector struct {
	Data       map[string]interface{} `json:"data"`
	Serialized string                 `json:"serialized"`
	JSON       interface{}            `json:"json"`
}

type SubstoreVector struct {
	Name string                 `json:"name"`
	Data map[string]interface{} `json:"data"`
}

func main() {
	// Fixed entropy for reproducibility
	entropy, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// Create identity
	vid, err := vaultysid.FromEntropy(entropy, vaultysid.TypePerson)
	if err != nil {
		panic(err)
	}

	// Create IdManager
	store := idmanager.NewMemoryStore()
	manager := idmanager.NewManager(vid, store)

	// Create test vectors
	vectors := IdManagerTestVectors{
		Description: "Comprehensive IdManager test vectors for TypeScript compatibility",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Version:     "1.0.0",
	}

	// Identity Management Vectors
	manager.SetName("Test User")
	manager.SetEmail("test@example.com")
	manager.SetPhone("+1234567890")

	vectors.Identity = IdentityManagerVectors{
		Entropy:     hex.EncodeToString(entropy),
		Type:        uint8(vid.Type),
		Name:        manager.Name(),
		Email:       manager.Email(),
		Phone:       manager.Phone(),
		DisplayName: manager.DisplayName(),
		DID:         vid.DID(),
		Metadata: map[string]interface{}{
			"name":  "Test User",
			"email": "test@example.com",
			"phone": "+1234567890",
		},
	}

	// Contact Management Vectors
	contactEntropies := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}

	for i, entropyHex := range contactEntropies {
		contactEntropy, _ := hex.DecodeString(entropyHex)
		contactVid, _ := vaultysid.FromEntropy(contactEntropy, vaultysid.TypePerson)

		metadata := map[string]interface{}{
			"name":     fmt.Sprintf("Contact %d", i+1),
			"email":    fmt.Sprintf("contact%d@example.com", i+1),
			"nickname": fmt.Sprintf("Nick%d", i+1),
		}

		manager.SaveContact(contactVid, metadata)

		vectors.Contacts.Contacts = append(vectors.Contacts.Contacts, ContactVector{
			Entropy:     entropyHex,
			DID:         contactVid.DID(),
			IDBytes:     hex.EncodeToString(contactVid.ID()),
			Certificate: "",
			Metadata:    metadata,
		})
	}

	// App Management Vectors
	apps := []struct {
		site     string
		serverID string
	}{
		{"app1.example.com", "server-id-001"},
		{"app2.example.com", "server-id-002"},
		{"app3.example.com", "server-id-003"},
	}

	for _, app := range apps {
		// Use the new SaveApp API that accepts a site string and optional serverID string
		manager.SaveApp(app.site, app.serverID)

		vectors.Apps.Apps = append(vectors.Apps.Apps, AppVector{
			Site:      app.site,
			ServerID:  app.serverID,
			Timestamp: crypto.Now(),
		})
	}

	// File Operations Vectors
	testFile := &idmanager.File{
		Name:        "test.txt",
		Type:        "text/plain",
		ArrayBuffer: []byte("Hello, VaultysID!"),
	}

	// File Signing
	signature, _ := manager.SignFile(testFile)
	vectors.Files.Signing = FileSigningVector{
		File: FileData{
			Name:       testFile.Name,
			Type:       testFile.Type,
			DataHex:    hex.EncodeToString(testFile.ArrayBuffer),
			DataBase64: base64.StdEncoding.EncodeToString(testFile.ArrayBuffer),
		},
		Signature: FileSignature{
			Challenge: hex.EncodeToString(signature.Challenge),
			Signature: hex.EncodeToString(signature.Signature),
		},
	}

	// File Encryption
	encryptedFile, _ := manager.EncryptFile(testFile)
	vectors.Files.Encryption = FileEncryptionVector{
		Original: FileData{
			Name:       testFile.Name,
			Type:       testFile.Type,
			DataHex:    hex.EncodeToString(testFile.ArrayBuffer),
			DataBase64: base64.StdEncoding.EncodeToString(testFile.ArrayBuffer),
		},
		Password: "", // No password used - encryption uses identity's HMAC
		Encrypted: FileData{
			Name:       encryptedFile.Name,
			Type:       encryptedFile.Type,
			DataHex:    hex.EncodeToString(encryptedFile.ArrayBuffer),
			DataBase64: base64.StdEncoding.EncodeToString(encryptedFile.ArrayBuffer),
		},
	}

	// Key Derivation Vectors

	// Protocol Key
	protocolKey, _ := manager.DeriveProtocolKey("https", 1)
	vectors.KeyDerivation.Protocol = ProtocolKeyVector{
		Protocol:  protocolKey.Protocol,
		Version:   protocolKey.Version,
		PublicKey: hex.EncodeToString(protocolKey.PublicKey),
	}

	// Service Key
	serviceKey, _ := manager.DeriveServiceKey("api.example.com", "https")
	vectors.KeyDerivation.Service = ServiceKeyVector{
		Service:   serviceKey.Service,
		Protocol:  serviceKey.Protocol,
		PublicKey: hex.EncodeToString(serviceKey.PublicKey),
	}

	// Encryption Key
	recipientDID := "did:vaultys:1234567890abcdef"
	encKey, _ := manager.DeriveEncryptionKey(recipientDID)
	vectors.KeyDerivation.Encryption = EncryptionKeyVector{
		RecipientDID: recipientDID,
		Key:          hex.EncodeToString(encKey),
	}

	// Signing Key
	signingContext := "document-signing"
	signingKey, _ := manager.DeriveSigningKey(signingContext)
	vectors.KeyDerivation.Signing = SigningKeyVector{
		Context: signingContext,
		Key:     hex.EncodeToString(signingKey),
	}

	// Session Key
	sessionID := "session-123"
	ttl := int64(3600000) // 1 hour in milliseconds
	sessionKey, _ := manager.DeriveSessionKey(sessionID, ttl)
	vectors.KeyDerivation.Session = SessionKeyVector{
		SessionID: sessionID,
		TTL:       ttl,
		Key:       hex.EncodeToString(sessionKey.Key),
	}

	// Channel Keys
	peerEntropy, _ := hex.DecodeString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	peerVid, _ := vaultysid.FromEntropy(peerEntropy, vaultysid.TypePerson)
	nonce := []byte("test-nonce-12345")
	channelEncKey, channelMacKey, _ := manager.DeriveChannelKeys(peerVid.GetCypherPublicKey(), nonce)
	vectors.KeyDerivation.Channel = ChannelKeyVector{
		PeerPublicKey: hex.EncodeToString(peerVid.GetCypherPublicKey()),
		Nonce:         hex.EncodeToString(nonce),
		EncKey:        hex.EncodeToString(channelEncKey),
		MacKey:        hex.EncodeToString(channelMacKey),
	}

	// HMAC Derivation
	hmacPurpose := "authentication"
	hmacMessage := []byte("test message")
	hmacResult, _ := manager.DeriveHMAC(hmacPurpose, hmacMessage)
	vectors.KeyDerivation.HMAC = HMACKeyVector{
		Purpose: hmacPurpose,
		Message: hex.EncodeToString(hmacMessage),
		Result:  hex.EncodeToString(hmacResult),
	}

	// PRF Vectors
	appID := "test-app"
	salts := []string{
		"73616c74313233", // "salt123" in hex
		"73616c74343536", // "salt456" in hex
		"73616c74373839", // "salt789" in hex
	}

	vectors.PRF.AppID = appID
	for _, saltHex := range salts {
		salt, _ := hex.DecodeString(saltHex)
		prf, _ := manager.PRF(appID, salt)
		vectors.PRF.Salts = append(vectors.PRF.Salts, saltHex)
		vectors.PRF.Results = append(vectors.PRF.Results, hex.EncodeToString(prf))
	}

	// Backup Vectors
	backupPassword := "backup-password-123"
	backup, _ := manager.ExportBackup(backupPassword)
	vectors.Backup = BackupVectors{
		Password:        backupPassword,
		EncryptedBackup: backup,
		Metadata: map[string]interface{}{
			"version":     1,
			"timestamp":   crypto.Now(),
			"hasContacts": len(manager.Contacts()) > 0,
			"hasApps":     len(manager.Apps()) > 0,
		},
	}

	// Challenge Signing Vectors
	challenge := []byte("test-challenge-data")

	// Protocol V0
	manager.SetProtocolVersion(0)
	signatureV0, _ := manager.SignChallenge(challenge)
	vectors.Challenge.ProtocolV0 = ChallengeVector{
		Challenge: hex.EncodeToString(challenge),
		Signature: hex.EncodeToString(signatureV0),
		Version:   0,
	}

	// Protocol V1
	manager.SetProtocolVersion(1)
	signatureV1, _ := manager.SignChallenge(challenge)
	vectors.Challenge.ProtocolV1 = ChallengeVector{
		Challenge: hex.EncodeToString(challenge),
		Signature: hex.EncodeToString(signatureV1),
		Version:   1,
	}

	// Storage Vectors
	testStore := idmanager.NewMemoryStore()
	testStore.Set("key1", "value1")
	testStore.Set("key2", 42)
	testStore.Set("key3", map[string]interface{}{
		"nested": "data",
		"number": 123,
	})

	// Create substores
	substore1 := testStore.Substore("sub1")
	substore1.Set("subkey1", "subvalue1")
	substore1.Set("subkey2", "subvalue2")

	substore2 := testStore.Substore("sub2")
	substore2.Set("data", map[string]interface{}{
		"field1": "value1",
		"field2": 999,
	})

	// Serialize store
	serialized, _ := testStore.ToString()
	jsonData, _ := testStore.ToJSON()

	vectors.Storage = StorageVectors{
		MemoryStore: StorageTestVector{
			Data: map[string]interface{}{
				"key1": "value1",
				"key2": 42,
				"key3": map[string]interface{}{
					"nested": "data",
					"number": 123,
				},
			},
			Serialized: base64.StdEncoding.EncodeToString([]byte(serialized)),
			JSON:       jsonData,
		},
		Substores: []SubstoreVector{
			{
				Name: "sub1",
				Data: map[string]interface{}{
					"subkey1": "subvalue1",
					"subkey2": "subvalue2",
				},
			},
			{
				Name: "sub2",
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"field1": "value1",
						"field2": 999,
					},
				},
			},
		},
	}

	// Write to file
	jsonBytes, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		panic(err)
	}

	outputPath := filepath.Join(".", "go-idmanager-vectors.json")
	if err := os.WriteFile(outputPath, jsonBytes, 0644); err != nil {
		panic(err)
	}

	fmt.Printf("Generated IdManager test vectors at %s\n", outputPath)
	fmt.Printf("Test vector categories:\n")
	fmt.Printf("  - Identity management\n")
	fmt.Printf("  - %d Contacts\n", len(vectors.Contacts.Contacts))
	fmt.Printf("  - %d Apps\n", len(vectors.Apps.Apps))
	fmt.Printf("  - File operations (signing & encryption)\n")
	fmt.Printf("  - Key derivation (7 types)\n")
	fmt.Printf("  - PRF with %d salts\n", len(vectors.PRF.Salts))
	fmt.Printf("  - Backup/restore\n")
	fmt.Printf("  - Challenge signing (v0 & v1)\n")
	fmt.Printf("  - Storage with %d substores\n", len(vectors.Storage.Substores))
}

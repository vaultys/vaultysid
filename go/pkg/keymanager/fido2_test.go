package keymanager

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/vaultys/vaultysid-go/pkg/crypto"
	"github.com/vmihailenco/msgpack/v5"
)

// Helper function to create a mock COSE Ed25519 key
func createMockEd25519COSEKey() ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	coseKey := COSEKey{
		1:  COSEKtyOKP,
		3:  COSEAlgEdDSA,
		-2: pub,
	}

	coseKeyBytes, _ := cbor.Marshal(coseKey)
	return coseKeyBytes, pub, priv
}

// Helper function to create a mock FIDO2 signature
func createMockFIDO2Signature(data, clientDataJSON, authData []byte, privateKey ed25519.PrivateKey) []byte {
	// Create signed data: authData || sha256(clientDataJSON)
	clientDataHash := crypto.Hash("sha256", clientDataJSON)
	signedData := append(authData, clientDataHash...)

	// Sign with Ed25519
	signature := ed25519.Sign(privateKey, signedData)

	// Pack into FIDO2Signature format
	sig := FIDO2Signature{
		S: signature,
		C: clientDataJSON,
		A: authData,
	}

	sigBytes, _ := msgpack.Marshal(sig)
	return sigBytes
}

// Helper function to create mock authenticator data
func createMockAuthenticatorData(rpIdHash []byte, flags byte, signCount uint32) []byte {
	authData := make([]byte, 37)
	copy(authData[:32], rpIdHash)
	authData[32] = flags
	// Sign count (big endian)
	authData[33] = byte(signCount >> 24)
	authData[34] = byte(signCount >> 16)
	authData[35] = byte(signCount >> 8)
	authData[36] = byte(signCount)
	return authData
}

func TestFIDO2Manager_FromSecret(t *testing.T) {
	// Create test data
	coseKey, _, _ := createMockEd25519COSEKey()
	cypherSecret := make([]byte, 32)
	rand.Read(cypherSecret)
	fid := make([]byte, 32)
	rand.Read(fid)

	secretData := ExportFIDO2Data{
		V: 1,
		F: fid,
		T: 15, // USB|NFC|BLE|Internal
		C: coseKey,
		E: cypherSecret,
	}

	secret, err := msgpack.Marshal(secretData)
	if err != nil {
		t.Fatalf("Failed to marshal secret: %v", err)
	}

	// Test FromSecret
	manager, err := FIDO2ManagerFromSecret(secret)
	if err != nil {
		t.Fatalf("Failed to create manager from secret: %v", err)
	}

	// Verify properties
	if manager.Version != 1 {
		t.Errorf("Expected version 1, got %d", manager.Version)
	}

	if manager.Capability != "private" {
		t.Errorf("Expected capability 'private', got %s", manager.Capability)
	}

	if !bytes.Equal(manager.FID, fid) {
		t.Errorf("FID mismatch")
	}

	if !bytes.Equal(manager.CKey, coseKey) {
		t.Errorf("CKey mismatch")
	}

	if manager.Transports != 15 {
		t.Errorf("Expected transports 15, got %d", manager.Transports)
	}

	if manager.AuthType != "Ed25519VerificationKey2020" {
		t.Errorf("Expected Ed25519VerificationKey2020, got %s", manager.AuthType)
	}
}

func TestFIDO2Manager_FromID(t *testing.T) {
	// Create test data
	coseKey, pubKey, _ := createMockEd25519COSEKey()
	cypherPublic := make([]byte, 32)
	rand.Read(cypherPublic)

	idData := ExportFIDO2ID{
		V: 1,
		C: coseKey,
		E: cypherPublic,
	}

	id, err := msgpack.Marshal(idData)
	if err != nil {
		t.Fatalf("Failed to marshal ID: %v", err)
	}

	// Test FromID
	manager, err := FIDO2ManagerFromID(id)
	if err != nil {
		t.Fatalf("Failed to create manager from ID: %v", err)
	}

	// Verify properties
	if manager.Version != 1 {
		t.Errorf("Expected version 1, got %d", manager.Version)
	}

	if manager.Capability != "public" {
		t.Errorf("Expected capability 'public', got %s", manager.Capability)
	}

	if !bytes.Equal(manager.CKey, coseKey) {
		t.Errorf("CKey mismatch")
	}

	if !bytes.Equal(manager.Cypher.PublicKey, cypherPublic) {
		t.Errorf("Cypher public key mismatch")
	}

	if !bytes.Equal(manager.Signer.PublicKey, pubKey) {
		t.Errorf("Signer public key mismatch")
	}
}

func TestFIDO2Manager_Verify(t *testing.T) {
	// Create a manager with Ed25519 key
	coseKey, pubKey, privKey := createMockEd25519COSEKey()

	manager := &FIDO2Manager{
		Version:    1,
		Capability: "public",
		CKey:       coseKey,
		AuthType:   "Ed25519VerificationKey2020",
		Signer: KeyPair{
			PublicKey: pubKey,
		},
	}

	// Create test data to sign
	testData := []byte("test message")
	challenge := crypto.Hash("sha256", testData)

	// Create mock client data JSON with base64url-encoded challenge
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)
	// Convert to base64url
	challengeB64 = strings.ReplaceAll(challengeB64, "+", "-")
	challengeB64 = strings.ReplaceAll(challengeB64, "/", "_")
	challengeB64 = strings.TrimRight(challengeB64, "=")
	clientDataJSON := []byte(`{"challenge":"` + challengeB64 + `","type":"webauthn.get"}`)

	// Create mock authenticator data
	rpIdHash := crypto.Hash("sha256", []byte("example.com"))
	flags := byte(0x01) // User present
	authData := createMockAuthenticatorData(rpIdHash, flags, 1)

	// Create signature
	signature := createMockFIDO2Signature(testData, clientDataJSON, authData, privKey)

	// Test verification
	err := manager.Verify(testData, signature)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	// Test with wrong data
	wrongData := []byte("wrong message")
	err = manager.Verify(wrongData, signature)
	if err == nil {
		t.Errorf("Expected verification to fail with wrong data")
	}
}

func TestFIDO2Manager_VerifyWithUserVerification(t *testing.T) {
	// Create a manager with Ed25519 key
	coseKey, pubKey, privKey := createMockEd25519COSEKey()

	manager := &FIDO2Manager{
		Version:    1,
		Capability: "public",
		CKey:       coseKey,
		AuthType:   "Ed25519VerificationKey2020",
		Signer: KeyPair{
			PublicKey: pubKey,
		},
	}

	// Create test data
	testData := []byte("test message")
	challenge := crypto.Hash("sha256", testData)
	// Create mock client data JSON with base64url-encoded challenge
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)
	// Convert to base64url
	challengeB64 = strings.ReplaceAll(challengeB64, "+", "-")
	challengeB64 = strings.ReplaceAll(challengeB64, "/", "_")
	challengeB64 = strings.TrimRight(challengeB64, "=")
	clientDataJSON := []byte(`{"challenge":"` + challengeB64 + `","type":"webauthn.get"}`)
	rpIdHash := crypto.Hash("sha256", []byte("example.com"))

	// Test with user verification flag set
	flagsWithUV := byte(0x05) // User present (0x01) | User verified (0x04)
	authDataWithUV := createMockAuthenticatorData(rpIdHash, flagsWithUV, 1)
	signatureWithUV := createMockFIDO2Signature(testData, clientDataJSON, authDataWithUV, privKey)

	err := manager.VerifyWithUserVerification(testData, signatureWithUV, true)
	if err != nil {
		t.Errorf("Verification with UV failed: %v", err)
	}

	// Test without user verification flag when required
	flagsWithoutUV := byte(0x01) // User present only
	authDataWithoutUV := createMockAuthenticatorData(rpIdHash, flagsWithoutUV, 1)
	signatureWithoutUV := createMockFIDO2Signature(testData, clientDataJSON, authDataWithoutUV, privKey)

	err = manager.VerifyWithUserVerification(testData, signatureWithoutUV, true)
	if err == nil {
		t.Errorf("Expected verification to fail when UV required but not present")
	}

	// Should succeed when UV not required
	err = manager.VerifyWithUserVerification(testData, signatureWithoutUV, false)
	if err != nil {
		t.Errorf("Verification without UV requirement failed: %v", err)
	}
}

func TestFIDO2Manager_Serialization(t *testing.T) {
	// Create test manager
	coseKey, _, _ := createMockEd25519COSEKey()
	cypherSecret := make([]byte, 32)
	rand.Read(cypherSecret)
	cypherPublic := make([]byte, 32)
	rand.Read(cypherPublic)
	fid := make([]byte, 32)
	rand.Read(fid)

	manager := &FIDO2Manager{
		Version:    1,
		Capability: "private",
		FID:        fid,
		CKey:       coseKey,
		Transports: 15,
		AuthType:   "Ed25519VerificationKey2020",
		Signer: KeyPair{
			PublicKey: make([]byte, 32),
		},
		Cypher: KeyPair{
			PublicKey: cypherPublic,
			SecretKey: cypherSecret,
		},
	}

	// Test GetSecret
	secret, err := manager.GetSecret()
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	// Recreate from secret
	manager2, err := FIDO2ManagerFromSecret(secret)
	if err != nil {
		t.Fatalf("Failed to recreate from secret: %v", err)
	}

	if !bytes.Equal(manager.FID, manager2.FID) {
		t.Errorf("FID mismatch after serialization")
	}

	if !bytes.Equal(manager.CKey, manager2.CKey) {
		t.Errorf("CKey mismatch after serialization")
	}

	// Test ToBytes (public ID)
	id := manager.ToBytes()

	// Recreate from ID
	manager3, err := FIDO2ManagerFromID(id)
	if err != nil {
		t.Fatalf("Failed to recreate from ID: %v", err)
	}

	if manager3.Capability != "public" {
		t.Errorf("Expected public capability from ID")
	}

	if !bytes.Equal(manager.Cypher.PublicKey, manager3.Cypher.PublicKey) {
		t.Errorf("Cypher public key mismatch after ID serialization")
	}
}

func TestFIDO2Manager_Transports(t *testing.T) {
	manager := &FIDO2Manager{
		Transports: 0,
	}

	// Test SetTransports
	transports := []string{"usb", "nfc", "internal"}
	manager.SetTransports(transports)

	expectedValue := 1 + 2 + 8 // usb + nfc + internal
	if manager.Transports != expectedValue {
		t.Errorf("Expected transports value %d, got %d", expectedValue, manager.Transports)
	}

	// Test GetTransports
	retrieved := manager.GetTransports()
	if len(retrieved) != 3 {
		t.Errorf("Expected 3 transports, got %d", len(retrieved))
	}

	// Check all expected transports are present
	transportMap := make(map[string]bool)
	for _, t := range retrieved {
		transportMap[t] = true
	}

	for _, expected := range transports {
		if !transportMap[expected] {
			t.Errorf("Missing expected transport: %s", expected)
		}
	}
}

func TestFIDO2Manager_DiffieHellman(t *testing.T) {
	// Create manager with private key
	cypherSecret := make([]byte, 32)
	rand.Read(cypherSecret)

	manager := &FIDO2Manager{
		Capability: "private",
		Cypher: KeyPair{
			SecretKey: cypherSecret,
		},
	}

	// Create peer public key
	peerPublic := make([]byte, 32)
	rand.Read(peerPublic)

	// Test DiffieHellman
	shared, err := manager.DiffieHellman(peerPublic)
	if err != nil {
		t.Fatalf("DiffieHellman failed: %v", err)
	}

	if len(shared) != 32 {
		t.Errorf("Expected 32-byte shared secret, got %d bytes", len(shared))
	}

	// Test without private key
	publicOnlyManager := &FIDO2Manager{
		Capability: "public",
	}

	_, err = publicOnlyManager.DiffieHellman(peerPublic)
	if err == nil {
		t.Errorf("Expected error when performing DH without private key")
	}
}

func TestFIDO2Manager_HMAC(t *testing.T) {
	// Create manager with private key
	cypherSecret := make([]byte, 32)
	rand.Read(cypherSecret)

	manager := &FIDO2Manager{
		Capability: "private",
		Cypher: KeyPair{
			SecretKey: cypherSecret,
		},
	}

	// Test HMAC
	message := "test-message"
	hmac, err := manager.HMAC(message)
	if err != nil {
		t.Fatalf("HMAC failed: %v", err)
	}

	if len(hmac) != 32 {
		t.Errorf("Expected 32-byte HMAC, got %d bytes", len(hmac))
	}

	// Verify HMAC is deterministic
	hmac2, _ := manager.HMAC(message)
	if !bytes.Equal(hmac, hmac2) {
		t.Errorf("HMAC not deterministic")
	}

	// Test without private key
	publicOnlyManager := &FIDO2Manager{
		Capability: "public",
	}

	_, err = publicOnlyManager.HMAC(message)
	if err == nil {
		t.Errorf("Expected error when computing HMAC without private key")
	}
}

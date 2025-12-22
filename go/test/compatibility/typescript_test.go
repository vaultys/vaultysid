package compatibility

import (
	"encoding/hex"
	"testing"

	"github.com/vaultys/vaultysid-go/pkg/keymanager"
	"github.com/vaultys/vaultysid-go/pkg/vaultysid"
)

// Test vectors generated from TypeScript implementation
// Run: cd typescript && npm run test:compatibility:export
var testVectors = struct {
	entropy          string
	ed25519PublicKey string
	x25519PublicKey  string
	signature        string
	signedData       string
	did              string
	idBytes          string
}{
	// These are placeholder values - replace with actual TypeScript output
	entropy:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	ed25519PublicKey: "", // Will be filled from TypeScript
	x25519PublicKey:  "", // Will be filled from TypeScript
	signature:        "", // Will be filled from TypeScript
	signedData:       "test message",
	did:              "", // Will be filled from TypeScript
	idBytes:          "", // Will be filled from TypeScript
}

func TestTypeScriptCompatibility_KeyGeneration(t *testing.T) {
	// Skip if test vectors not populated
	if testVectors.ed25519PublicKey == "" {
		t.Skip("Test vectors not populated. Run TypeScript test:compatibility:export first")
	}

	entropy, _ := hex.DecodeString(testVectors.entropy)
	km, err := keymanager.CreateFromEntropy(entropy)
	if err != nil {
		t.Fatal(err)
	}

	// Cast to Ed25519Manager to access specific fields
	ed25519km, ok := km.(*keymanager.Ed25519Manager)
	if !ok {
		t.Fatal("KeyManager is not an Ed25519Manager")
	}

	// Check Ed25519 public key matches
	expectedPK, _ := hex.DecodeString(testVectors.ed25519PublicKey)
	if hex.EncodeToString(ed25519km.Signer.PublicKey) != hex.EncodeToString(expectedPK) {
		t.Errorf("Ed25519 public key mismatch:\nGot:      %x\nExpected: %x",
			ed25519km.Signer.PublicKey, expectedPK)
	}

	// Check X25519 public key matches
	expectedCypher, _ := hex.DecodeString(testVectors.x25519PublicKey)
	if hex.EncodeToString(ed25519km.Cypher.PublicKey) != hex.EncodeToString(expectedCypher) {
		t.Errorf("X25519 public key mismatch:\nGot:      %x\nExpected: %x",
			ed25519km.Cypher.PublicKey, expectedCypher)
	}
}

func TestTypeScriptCompatibility_Signature(t *testing.T) {
	if testVectors.signature == "" {
		t.Skip("Test vectors not populated")
	}

	entropy, _ := hex.DecodeString(testVectors.entropy)
	km, _ := keymanager.CreateFromEntropy(entropy)

	// Sign the test data
	sig, err := km.Sign([]byte(testVectors.signedData))
	if err != nil {
		t.Fatal(err)
	}

	expectedSig, _ := hex.DecodeString(testVectors.signature)
	if hex.EncodeToString(sig) != hex.EncodeToString(expectedSig) {
		t.Errorf("Signature mismatch:\nGot:      %x\nExpected: %x",
			sig, expectedSig)
	}

	// Verify TypeScript signature with our public key
	if err := km.Verify([]byte(testVectors.signedData), expectedSig); err != nil {
		t.Error("Failed to verify TypeScript signature")
	}
}

func TestTypeScriptCompatibility_DID(t *testing.T) {
	if testVectors.did == "" {
		t.Skip("Test vectors not populated")
	}

	entropy, _ := hex.DecodeString(testVectors.entropy)
	vid, err := vaultysid.FromEntropy(entropy, vaultysid.TypePerson)
	if err != nil {
		t.Fatal(err)
	}

	if vid.DID() != testVectors.did {
		t.Errorf("DID mismatch:\nGot:      %s\nExpected: %s",
			vid.DID(), testVectors.did)
	}
}

func TestTypeScriptCompatibility_Serialization(t *testing.T) {
	if testVectors.idBytes == "" {
		t.Skip("Test vectors not populated")
	}

	entropy, _ := hex.DecodeString(testVectors.entropy)
	vid, _ := vaultysid.FromEntropy(entropy, vaultysid.TypePerson)

	idBytes := vid.ToBytes()
	expectedID, _ := hex.DecodeString(testVectors.idBytes)

	if hex.EncodeToString(idBytes) != hex.EncodeToString(expectedID) {
		t.Errorf("ID bytes mismatch:\nGot:      %x\nExpected: %x",
			idBytes, expectedID)
	}

	// Try to deserialize TypeScript ID
	restored, err := vaultysid.FromID(expectedID, nil)
	if err != nil {
		t.Fatalf("Failed to deserialize TypeScript ID: %v", err)
	}

	if restored.Type != vaultysid.TypePerson {
		t.Error("Type not preserved after deserialization")
	}
}

func TestTypeScriptCompatibility_CrossVerification(t *testing.T) {
	// This test would use actual signatures from TypeScript
	// to verify interoperability

	// Example structure:
	tsTestCases := []struct {
		name      string
		publicKey string // hex
		message   string
		signature string // hex
	}{
		// Add actual test cases from TypeScript here
	}

	for _, tc := range tsTestCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.publicKey == "" {
				t.Skip("Test case not populated")
				return
			}

			pk, _ := hex.DecodeString(tc.publicKey)
			sig, _ := hex.DecodeString(tc.signature)

			// Create a public-only key manager
			// This would need a FromPublicKey method
			// For now, skip implementation
			_ = pk
			_ = sig
		})
	}
}

// TestGenerateTypeScriptVectors generates test vectors for TypeScript to verify
func TestGenerateTypeScriptVectors(t *testing.T) {
	t.Skip("Run manually to generate vectors")

	// Use fixed entropy for reproducible results
	entropy, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	km, _ := keymanager.CreateFromEntropy(entropy)
	vid, _ := vaultysid.FromEntropy(entropy, vaultysid.TypePerson)

	// Cast to Ed25519Manager to access specific fields
	ed25519km, ok := km.(*keymanager.Ed25519Manager)
	if !ok {
		t.Fatal("KeyManager is not an Ed25519Manager")
	}

	// Sign a message
	message := []byte("test message")
	sig, _ := km.Sign(message)

	t.Logf("Test vectors for TypeScript:")
	t.Logf("Entropy: %x", entropy)
	t.Logf("Ed25519 Public Key: %x", ed25519km.Signer.PublicKey)
	t.Logf("X25519 Public Key: %x", ed25519km.Cypher.PublicKey)
	t.Logf("Message: %s", message)
	t.Logf("Signature: %x", sig)
	t.Logf("DID: %s", vid.DID())
	t.Logf("ID Bytes: %x", vid.ToBytes())
}

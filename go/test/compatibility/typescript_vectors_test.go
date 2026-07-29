package compatibility

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

type TestVectors struct {
	KeyGeneration struct {
		Entropy string `json:"entropy"`
		Ed25519 struct {
			PublicKey string `json:"publicKey"`
			SecretKey string `json:"secretKey"`
		} `json:"ed25519"`
		X25519 struct {
			PublicKey string `json:"publicKey"`
			SecretKey string `json:"secretKey"`
		} `json:"x25519"`
	} `json:"keyGeneration"`

	Identity struct {
		Type          int    `json:"type"`
		DID           string `json:"did"`
		IDBytes       string `json:"idBytes"`
		IDBytesLength int    `json:"idBytesLength"`
	} `json:"identity"`

	Signing struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	} `json:"signing"`

	DiffieHellman struct {
		AliceEntropy string `json:"aliceEntropy"`
		BobEntropy   string `json:"bobEntropy"`
		BobPublicKey string `json:"bobPublicKey"`
		SharedSecret string `json:"sharedSecret"`
	} `json:"diffieHellman"`

	HMAC struct {
		Message string `json:"message"`
		Result  string `json:"result"`
	} `json:"hmac"`

	AdditionalSignatures []struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	} `json:"additionalSignatures"`
}

func loadTypeScriptVectors(t *testing.T) *TestVectors {
	// Try to find test vectors file
	paths := []string{
		"../../typescript/test/interops/test-vectors.json",
		"../../../typescript/test/interops/test-vectors.json",
		"../../../../typescript/test/interops/test-vectors.json",
	}

	var data []byte
	var err error
	var foundPath string

	for _, path := range paths {
		data, err = os.ReadFile(path)
		if err == nil {
			foundPath = path
			break
		}
	}

	if foundPath == "" {
		absPath, _ := filepath.Abs(".")
		t.Skipf("Test vectors not found. Current dir: %s\nRun 'cd typescript && pnpm tsx test/interops/generate-vectors.ts' first", absPath)
	}

	var vectors TestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}

	return &vectors
}

func TestTypeScriptVectors_KeyGeneration(t *testing.T) {
	vectors := loadTypeScriptVectors(t)

	entropy, _ := hex.DecodeString(vectors.KeyGeneration.Entropy)
	km, err := keymanager.CreateFromEntropy(entropy)
	if err != nil {
		t.Fatal(err)
	}

	// Cast to Ed25519Manager to access specific fields
	ed25519km, ok := km.(*keymanager.Ed25519Manager)
	if !ok {
		t.Fatal("KeyManager is not an Ed25519Manager")
	}

	// Check Ed25519 public key
	expectedEd25519, _ := hex.DecodeString(vectors.KeyGeneration.Ed25519.PublicKey)
	if hex.EncodeToString(ed25519km.Signer.PublicKey) != hex.EncodeToString(expectedEd25519) {
		t.Errorf("Ed25519 public key mismatch:\nGot:      %x\nExpected: %x",
			ed25519km.Signer.PublicKey, expectedEd25519)
	}

	// Check X25519 public key
	expectedX25519, _ := hex.DecodeString(vectors.KeyGeneration.X25519.PublicKey)
	if hex.EncodeToString(ed25519km.Cypher.PublicKey) != hex.EncodeToString(expectedX25519) {
		t.Errorf("X25519 public key mismatch:\nGot:      %x\nExpected: %x",
			ed25519km.Cypher.PublicKey, expectedX25519)
	}
}

func TestTypeScriptVectors_Identity(t *testing.T) {
	vectors := loadTypeScriptVectors(t)

	entropy, _ := hex.DecodeString(vectors.KeyGeneration.Entropy)
	vid, err := vaultysid.FromEntropy(entropy, vaultysid.IdentityType(vectors.Identity.Type))
	if err != nil {
		t.Fatal(err)
	}

	// Check ID bytes
	idBytes := vid.ToBytes()
	expectedID, _ := hex.DecodeString(vectors.Identity.IDBytes)

	if len(idBytes) != vectors.Identity.IDBytesLength {
		t.Errorf("ID length mismatch: got %d, expected %d", len(idBytes), vectors.Identity.IDBytesLength)
	}

	if hex.EncodeToString(idBytes) != hex.EncodeToString(expectedID) {
		t.Errorf("ID bytes mismatch:\nGot:      %x\nExpected: %x", idBytes, expectedID)
	}

	// Check DID
	if vid.DID() != vectors.Identity.DID {
		t.Errorf("DID mismatch:\nGot:      %s\nExpected: %s", vid.DID(), vectors.Identity.DID)
	}
}

func TestTypeScriptVectors_Signing(t *testing.T) {
	vectors := loadTypeScriptVectors(t)

	entropy, _ := hex.DecodeString(vectors.KeyGeneration.Entropy)
	km, _ := keymanager.CreateFromEntropy(entropy)

	message, _ := hex.DecodeString(vectors.Signing.Message)
	expectedSig, _ := hex.DecodeString(vectors.Signing.Signature)

	// Sign with Go
	sig, err := km.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	// Check signature matches TypeScript
	if hex.EncodeToString(sig) != hex.EncodeToString(expectedSig) {
		t.Errorf("Signature mismatch:\nGot:      %x\nExpected: %x", sig, expectedSig)
	}

	// Verify TypeScript signature with Go
	if err := km.Verify(message, expectedSig); err != nil {
		t.Error("Failed to verify TypeScript signature with Go")
	}
}

func TestTypeScriptVectors_DiffieHellman(t *testing.T) {
	vectors := loadTypeScriptVectors(t)

	aliceEntropy, _ := hex.DecodeString(vectors.DiffieHellman.AliceEntropy)
	bobEntropy, _ := hex.DecodeString(vectors.DiffieHellman.BobEntropy)

	alice, _ := keymanager.CreateFromEntropy(aliceEntropy)
	bob, _ := keymanager.CreateFromEntropy(bobEntropy)

	// Cast to Ed25519Manager to access specific fields
	bobEd25519, ok := bob.(*keymanager.Ed25519Manager)
	if !ok {
		t.Fatal("Bob's KeyManager is not an Ed25519Manager")
	}

	// Check Bob's public key matches
	expectedBobPK, _ := hex.DecodeString(vectors.DiffieHellman.BobPublicKey)
	if hex.EncodeToString(bobEd25519.Cypher.PublicKey) != hex.EncodeToString(expectedBobPK) {
		t.Errorf("Bob's public key mismatch:\nGot:      %x\nExpected: %x",
			bobEd25519.Cypher.PublicKey, expectedBobPK)
	}

	// Compute shared secret
	shared, err := alice.DiffieHellman(bob.GetCypherPublicKey())
	if err != nil {
		t.Fatal(err)
	}

	expectedShared, _ := hex.DecodeString(vectors.DiffieHellman.SharedSecret)
	if hex.EncodeToString(shared) != hex.EncodeToString(expectedShared) {
		t.Errorf("Shared secret mismatch:\nGot:      %x\nExpected: %x",
			shared, expectedShared)
	}
}

func TestTypeScriptVectors_HMAC(t *testing.T) {
	vectors := loadTypeScriptVectors(t)

	entropy, _ := hex.DecodeString(vectors.KeyGeneration.Entropy)
	km, _ := keymanager.CreateFromEntropy(entropy)

	hmac, err := km.HMAC(vectors.HMAC.Message)
	if err != nil {
		t.Fatal(err)
	}

	expectedHMAC, _ := hex.DecodeString(vectors.HMAC.Result)
	if hex.EncodeToString(hmac) != hex.EncodeToString(expectedHMAC) {
		t.Errorf("HMAC mismatch:\nGot:      %x\nExpected: %x",
			hmac, expectedHMAC)
	}
}

func TestTypeScriptVectors_AdditionalSignatures(t *testing.T) {
	vectors := loadTypeScriptVectors(t)

	entropy, _ := hex.DecodeString(vectors.KeyGeneration.Entropy)
	km, _ := keymanager.CreateFromEntropy(entropy)

	for i, testCase := range vectors.AdditionalSignatures {
		var message []byte
		if testCase.Message == "" {
			message = []byte{}
		} else if testCase.Message == "VaultysID" {
			message = []byte("VaultysID")
		} else {
			message, _ = hex.DecodeString(testCase.Message)
		}

		expectedSig, _ := hex.DecodeString(testCase.Signature)

		// Verify TypeScript signature
		if err := km.Verify(message, expectedSig); err != nil {
			t.Errorf("Test case %d: Failed to verify TypeScript signature for message %x", i, message)
		}

		// Generate our own signature
		sig, err := km.Sign(message)
		if err != nil {
			t.Errorf("Test case %d: Failed to sign: %v", i, err)
			continue
		}

		// Check it matches
		if hex.EncodeToString(sig) != hex.EncodeToString(expectedSig) {
			t.Errorf("Test case %d: Signature mismatch for message %x:\nGot:      %x\nExpected: %x",
				i, message, sig, expectedSig)
		}
	}
}

func TestTypeScriptVectors_CrossCompatibility(t *testing.T) {
	vectors := loadTypeScriptVectors(t)

	// Load TypeScript-generated identity
	tsIDBytes, _ := hex.DecodeString(vectors.Identity.IDBytes)
	tsVID, err := vaultysid.FromID(tsIDBytes, nil)
	if err != nil {
		t.Fatalf("Failed to load TypeScript identity: %v", err)
	}

	// Verify it can verify TypeScript signatures
	message, _ := hex.DecodeString(vectors.Signing.Message)
	signature, _ := hex.DecodeString(vectors.Signing.Signature)

	if err := tsVID.Verify(message, signature); err != nil {
		t.Error("Failed to verify TypeScript signature with TypeScript-generated identity loaded in Go")
	}

	// Generate Go identity from same entropy
	entropy, _ := hex.DecodeString(vectors.KeyGeneration.Entropy)
	goVID, _ := vaultysid.FromEntropy(entropy, vaultysid.IdentityType(vectors.Identity.Type))

	// Sign with Go
	goSig, err := goVID.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	// Should match TypeScript signature
	if hex.EncodeToString(goSig) != hex.EncodeToString(signature) {
		t.Error("Go signature doesn't match TypeScript signature for same entropy and message")
	}
}

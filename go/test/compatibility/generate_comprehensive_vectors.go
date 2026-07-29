//go:build ignore
// +build ignore

// Run this file with: go run generate_comprehensive_vectors.go
// It generates comprehensive test vectors for TypeScript compatibility testing

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

type ComprehensiveTestVectors struct {
	Description   string                  `json:"description"`
	Timestamp     string                  `json:"timestamp"`
	Version       string                  `json:"version"`
	KeyGen        KeyGenerationVectors    `json:"keyGeneration"`
	Identity      IdentityVectors         `json:"identity"`
	Signing       SigningVectors          `json:"signing"`
	DH            DiffieHellmanVectors    `json:"diffieHellman"`
	HMAC          HMACVectors             `json:"hmac"`
	Serialization SerializationVectors    `json:"serialization"`
	Challenge     ChallengeVectors        `json:"challenge"`
	CrossTests    []CrossVerificationTest `json:"crossVerification"`
}

type KeyGenerationVectors struct {
	Entropy string `json:"entropy"`
	Ed25519 struct {
		PublicKey string `json:"publicKey"`
		SecretKey string `json:"secretKey"`
	} `json:"ed25519"`
	X25519 struct {
		PublicKey string `json:"publicKey"`
		SecretKey string `json:"secretKey"`
	} `json:"x25519"`
}

type IdentityVectors struct {
	Type          uint8  `json:"type"`
	TypeName      string `json:"typeName"`
	IDBytes       string `json:"idBytes"`
	IDBytesLength int    `json:"idBytesLength"`
	DID           string `json:"did"`
	Version       int    `json:"version"`
}

type SigningVectors struct {
	Message         string              `json:"message"`
	MessageHex      string              `json:"messageHex"`
	Signature       string              `json:"signature"`
	AdditionalTests []SignatureTestCase `json:"additionalSignatures"`
}

type SignatureTestCase struct {
	Name       string `json:"name"`
	Message    string `json:"message"`
	MessageHex string `json:"messageHex"`
	Signature  string `json:"signature"`
}

type DiffieHellmanVectors struct {
	AliceEntropy   string `json:"aliceEntropy"`
	BobEntropy     string `json:"bobEntropy"`
	AlicePublicKey string `json:"alicePublicKey"`
	BobPublicKey   string `json:"bobPublicKey"`
	SharedSecret   string `json:"sharedSecret"`
}

type HMACVectors struct {
	Message string `json:"message"`
	Result  string `json:"result"`
}

type SerializationVectors struct {
	Secret       string `json:"secret"`
	PublicID     string `json:"publicId"`
	SecretBase64 string `json:"secretBase64"`
	PublicBase64 string `json:"publicBase64"`
}

type ChallengeVectors struct {
	AliceEntropy string          `json:"aliceEntropy"`
	BobEntropy   string          `json:"bobEntropy"`
	Protocol     string          `json:"protocol"`
	Service      string          `json:"service"`
	Steps        []ChallengeStep `json:"steps"`
}

type ChallengeStep struct {
	Name        string `json:"name"`
	State       int    `json:"state"`
	From        string `json:"from"`
	To          string `json:"to"`
	MessageHex  string `json:"messageHex"`
	HasPK1      bool   `json:"hasPk1"`
	HasPK2      bool   `json:"hasPk2"`
	HasSign1    bool   `json:"hasSign1"`
	HasSign2    bool   `json:"hasSign2"`
	NonceLength int    `json:"nonceLength"`
}

type CrossVerificationTest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Entropy     string `json:"entropy"`
	Type        uint8  `json:"type"`
	Message     string `json:"message"`
	Signature   string `json:"signature"`
	DID         string `json:"did"`
	IDBytes     string `json:"idBytes"`
	CanVerify   bool   `json:"canVerify"`
}

func main() {
	// Fixed entropy for reproducibility
	entropy, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// Generate key manager
	km, err := keymanager.CreateFromEntropy(entropy)
	if err != nil {
		panic(err)
	}

	// Cast to Ed25519Manager to access internals
	ed25519km := km.(*keymanager.Ed25519Manager)

	// Generate identity
	vid, err := vaultysid.FromEntropy(entropy, vaultysid.TypePerson)
	if err != nil {
		panic(err)
	}

	// Create comprehensive test vectors
	vectors := ComprehensiveTestVectors{
		Description: "Comprehensive Go-generated test vectors for TypeScript compatibility",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Version:     "2.0.0",
	}

	// Key Generation Vectors
	vectors.KeyGen.Entropy = hex.EncodeToString(entropy)
	vectors.KeyGen.Ed25519.PublicKey = hex.EncodeToString(ed25519km.Signer.PublicKey)
	vectors.KeyGen.Ed25519.SecretKey = hex.EncodeToString(ed25519km.Signer.SecretKey)
	vectors.KeyGen.X25519.PublicKey = hex.EncodeToString(ed25519km.Cypher.PublicKey)
	vectors.KeyGen.X25519.SecretKey = hex.EncodeToString(ed25519km.Cypher.SecretKey)

	// Identity Vectors
	vectors.Identity.Type = uint8(vid.Type)
	vectors.Identity.TypeName = vid.GetType()
	vectors.Identity.IDBytes = hex.EncodeToString(vid.ToBytes())
	vectors.Identity.IDBytesLength = len(vid.ToBytes())
	vectors.Identity.DID = vid.DID()
	vectors.Identity.Version = vid.GetVersion()

	// Signing Vectors
	message := []byte("test message")
	signature, _ := vid.Sign(message)
	vectors.Signing.Message = string(message)
	vectors.Signing.MessageHex = hex.EncodeToString(message)
	vectors.Signing.Signature = hex.EncodeToString(signature)

	// Additional signature tests
	additionalTests := []struct {
		name    string
		message []byte
	}{
		{"empty", []byte{}},
		{"vaultysid", []byte("VaultysID")},
		{"long", []byte("This is a longer message to test signing and verification across implementations")},
		{"binary", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}},
		{"unicode", []byte("Hello 世界 🌍")},
	}

	for _, test := range additionalTests {
		sig, _ := vid.Sign(test.message)
		vectors.Signing.AdditionalTests = append(vectors.Signing.AdditionalTests, SignatureTestCase{
			Name:       test.name,
			Message:    string(test.message),
			MessageHex: hex.EncodeToString(test.message),
			Signature:  hex.EncodeToString(sig),
		})
	}

	// Diffie-Hellman Vectors
	aliceEntropy, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bobEntropy, _ := hex.DecodeString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	alice, _ := keymanager.CreateFromEntropy(aliceEntropy)
	bob, _ := keymanager.CreateFromEntropy(bobEntropy)

	sharedSecret, _ := alice.DiffieHellman(bob.GetCypherPublicKey())

	vectors.DH.AliceEntropy = hex.EncodeToString(aliceEntropy)
	vectors.DH.BobEntropy = hex.EncodeToString(bobEntropy)
	vectors.DH.AlicePublicKey = hex.EncodeToString(alice.GetCypherPublicKey())
	vectors.DH.BobPublicKey = hex.EncodeToString(bob.GetCypherPublicKey())
	vectors.DH.SharedSecret = hex.EncodeToString(sharedSecret)

	// HMAC Vectors
	hmacMessage := "test/hmac/message"
	hmacResult, _ := km.HMAC(hmacMessage)
	vectors.HMAC.Message = hmacMessage
	vectors.HMAC.Result = hex.EncodeToString(hmacResult)

	// Serialization Vectors
	secret, _ := vid.GetSecret()
	vectors.Serialization.Secret = hex.EncodeToString(secret)
	vectors.Serialization.PublicID = hex.EncodeToString(vid.ToBytes())

	secretB64, _ := vid.GetSecretString("base64")
	publicB64, _ := vid.ToString("base64")
	vectors.Serialization.SecretBase64 = secretB64
	vectors.Serialization.PublicBase64 = publicB64

	// Challenge Protocol Vectors
	aliceVID, _ := vaultysid.FromEntropy(aliceEntropy, vaultysid.TypePerson)
	bobVID, _ := vaultysid.FromEntropy(bobEntropy, vaultysid.TypePerson)

	aliceChallenger := challenger.NewChallenger(aliceVID, nil)
	bobChallenger := challenger.NewChallenger(bobVID, nil)

	vectors.Challenge.AliceEntropy = hex.EncodeToString(aliceEntropy)
	vectors.Challenge.BobEntropy = hex.EncodeToString(bobEntropy)
	vectors.Challenge.Protocol = "test-protocol"
	vectors.Challenge.Service = "test-service"

	// Step 1: Alice initiates
	initChallenge, _ := aliceChallenger.Init("test-protocol", "test-service")
	initBytes, _ := challenger.Serialize(initChallenge)
	vectors.Challenge.Steps = append(vectors.Challenge.Steps, ChallengeStep{
		Name:        "init",
		State:       initChallenge.State,
		From:        "alice",
		To:          "bob",
		MessageHex:  hex.EncodeToString(initBytes),
		HasPK1:      initChallenge.HasPK1(),
		HasPK2:      initChallenge.HasPK2(),
		HasSign1:    initChallenge.HasSign1(),
		HasSign2:    initChallenge.HasSign2(),
		NonceLength: len(initChallenge.Nonce),
	})

	// Step 2: Bob responds
	step1Challenge, _ := bobChallenger.Step1(initChallenge)
	step1Bytes, _ := challenger.Serialize(step1Challenge)
	vectors.Challenge.Steps = append(vectors.Challenge.Steps, ChallengeStep{
		Name:        "step1",
		State:       step1Challenge.State,
		From:        "bob",
		To:          "alice",
		MessageHex:  hex.EncodeToString(step1Bytes),
		HasPK1:      step1Challenge.HasPK1(),
		HasPK2:      step1Challenge.HasPK2(),
		HasSign1:    step1Challenge.HasSign1(),
		HasSign2:    step1Challenge.HasSign2(),
		NonceLength: len(step1Challenge.Nonce),
	})

	// Step 3: Alice completes
	completeChallenge, _ := aliceChallenger.Step2(step1Challenge)
	completeBytes, _ := challenger.Serialize(completeChallenge)
	vectors.Challenge.Steps = append(vectors.Challenge.Steps, ChallengeStep{
		Name:        "complete",
		State:       completeChallenge.State,
		From:        "alice",
		To:          "bob",
		MessageHex:  hex.EncodeToString(completeBytes),
		HasPK1:      completeChallenge.HasPK1(),
		HasPK2:      completeChallenge.HasPK2(),
		HasSign1:    completeChallenge.HasSign1(),
		HasSign2:    completeChallenge.HasSign2(),
		NonceLength: len(completeChallenge.Nonce),
	})

	// Cross-verification tests
	testCases := []struct {
		name        string
		description string
		entropy     string
		idType      vaultysid.IdentityType
		message     string
	}{
		{
			name:        "machine_identity",
			description: "Machine identity cross-verification",
			entropy:     "1111111111111111111111111111111111111111111111111111111111111111",
			idType:      vaultysid.TypeMachine,
			message:     "machine test message",
		},
		{
			name:        "person_identity",
			description: "Person identity cross-verification",
			entropy:     "2222222222222222222222222222222222222222222222222222222222222222",
			idType:      vaultysid.TypePerson,
			message:     "person test message",
		},
		{
			name:        "organization_identity",
			description: "Organization identity cross-verification",
			entropy:     "3333333333333333333333333333333333333333333333333333333333333333",
			idType:      vaultysid.TypeOrganization,
			message:     "organization test message",
		},
	}

	for _, tc := range testCases {
		entropy, _ := hex.DecodeString(tc.entropy)
		vid, _ := vaultysid.FromEntropy(entropy, tc.idType)
		message := []byte(tc.message)
		signature, _ := vid.Sign(message)

		vectors.CrossTests = append(vectors.CrossTests, CrossVerificationTest{
			Name:        tc.name,
			Description: tc.description,
			Entropy:     tc.entropy,
			Type:        uint8(tc.idType),
			Message:     tc.message,
			Signature:   hex.EncodeToString(signature),
			DID:         vid.DID(),
			IDBytes:     hex.EncodeToString(vid.ToBytes()),
			CanVerify:   true,
		})
	}

	// Write to file
	jsonBytes, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		panic(err)
	}

	outputPath := filepath.Join(".", "go-comprehensive-vectors.json")
	if err := os.WriteFile(outputPath, jsonBytes, 0644); err != nil {
		panic(err)
	}

	fmt.Printf("Generated comprehensive test vectors at %s\n", outputPath)
	fmt.Printf("Total test cases: %d\n", len(vectors.CrossTests)+len(vectors.Signing.AdditionalTests)+len(vectors.Challenge.Steps))
}

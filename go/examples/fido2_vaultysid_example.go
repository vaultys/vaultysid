package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/fxamacker/cbor/v2"
	"github.com/vaultys/vaultysid-go/pkg/keymanager"
	"github.com/vaultys/vaultysid-go/pkg/vaultysid"
	"github.com/vmihailenco/msgpack/v5"
)

// Example demonstrates FIDO2Manager usage with VaultysID
// Note: Since FIDO2 signing requires browser WebAuthn API, this example
// focuses on verification and key management capabilities
func main() {
	fmt.Println("=== FIDO2 VaultysID Example ===")

	// Example 1: Creating a FIDO2 VaultysID from a secret (private key)
	demonstrateFIDO2FromSecret()

	// Example 2: Creating a FIDO2 VaultysID from a public ID
	demonstrateFIDO2FromPublicID()

	// Example 3: Verifying FIDO2 signatures
	demonstrateFIDO2Verification()

	// Example 4: Diffie-Hellman key exchange between FIDO2 identities
	demonstrateFIDO2DiffieHellman()

	// Example 5: Interoperability with TypeScript implementation
	demonstrateInteroperability()
}

func demonstrateFIDO2FromSecret() {
	fmt.Println("1. Creating FIDO2 VaultysID from secret")
	fmt.Println("----------------------------------------")

	// This is a mock secret that would normally come from a FIDO2 authenticator
	// In production, this would be obtained through the browser's WebAuthn API
	mockCOSEKey := createMockCOSEKey()
	mockFID := []byte("mock-fido2-credential-id")
	mockCypherSecret := make([]byte, 32)
	for i := range mockCypherSecret {
		mockCypherSecret[i] = byte(i)
	}

	// Create the FIDO2 secret data structure
	secretData := keymanager.ExportFIDO2Data{
		V: 1,
		F: mockFID,
		T: 15, // USB | NFC | BLE | Internal
		C: mockCOSEKey,
		E: mockCypherSecret,
	}

	// Marshal to msgpack format
	secretBytes, err := msgpack.Marshal(secretData)
	if err != nil {
		log.Printf("Failed to marshal secret data: %v", err)
		return
	}

	// Prepend the FIDO2 type byte
	fullSecret := append([]byte{byte(vaultysid.TypeFIDO2)}, secretBytes...)

	// Create VaultysID from secret
	vid, err := vaultysid.FromSecret(fullSecret)
	if err != nil {
		log.Printf("Failed to create VaultysID from secret: %v", err)
		return
	}

	fmt.Printf("Created FIDO2 VaultysID:\n")
	fmt.Printf("  Type: %s\n", vid.Type.String())
	fmt.Printf("  Auth Type: %s\n", vid.KeyManager.GetAuthType())
	fmt.Printf("  Enc Type: %s\n", vid.KeyManager.GetEncType())
	fmt.Printf("  Capability: %s\n", vid.KeyManager.GetCapability())

	// Get the ID for sharing
	id := vid.ID()
	fmt.Printf("  Public ID (hex): %s\n", hex.EncodeToString(id)[:64]+"...")

	// Get DID
	did := vid.DID()
	fmt.Printf("  DID: %s\n", did)

	fmt.Println()
}

func demonstrateFIDO2FromPublicID() {
	fmt.Println("2. Creating FIDO2 VaultysID from public ID")
	fmt.Println("-------------------------------------------")

	// Create a public ID data structure
	mockCOSEKey := createMockCOSEKey()
	mockCypherPublic := make([]byte, 32)
	for i := range mockCypherPublic {
		mockCypherPublic[i] = byte(i + 100)
	}

	idData := keymanager.ExportFIDO2ID{
		V: 1,
		C: mockCOSEKey,
		E: mockCypherPublic,
	}

	// Marshal to msgpack format
	idBytes, err := msgpack.Marshal(idData)
	if err != nil {
		log.Printf("Failed to marshal ID data: %v", err)
		return
	}

	// Prepend the FIDO2 type byte
	fullID := append([]byte{byte(vaultysid.TypeFIDO2)}, idBytes...)

	// Create VaultysID from ID
	vid, err := vaultysid.FromID(fullID, nil)
	if err != nil {
		log.Printf("Failed to create VaultysID from ID: %v", err)
		return
	}

	fmt.Printf("Created public FIDO2 VaultysID:\n")
	fmt.Printf("  Type: %s\n", vid.Type.String())
	fmt.Printf("  Capability: %s (no private key)\n", vid.KeyManager.GetCapability())
	fmt.Printf("  Can verify signatures: Yes\n")
	fmt.Printf("  Can sign: No (requires WebAuthn)\n")

	// Check if it's a hardware identity
	if vid.IsHardware() {
		fmt.Printf("  Hardware-backed: Yes\n")
	}

	fmt.Println()
}

func demonstrateFIDO2Verification() {
	fmt.Println("3. Verifying FIDO2 signatures")
	fmt.Println("------------------------------")

	// Create a mock FIDO2Manager for verification
	mockCOSEKey := createMockEd25519COSEKey()

	idData := keymanager.ExportFIDO2ID{
		V: 1,
		C: mockCOSEKey,
		E: make([]byte, 32),
	}

	idBytes, _ := msgpack.Marshal(idData)
	fullID := append([]byte{byte(vaultysid.TypeFIDO2)}, idBytes...)

	vid, err := vaultysid.FromID(fullID, nil)
	if err != nil {
		log.Printf("Failed to create VaultysID: %v", err)
		return
	}

	// In production, the signature would come from a FIDO2 authenticator
	// Here we demonstrate the structure and verification flow
	testData := []byte("Message to be verified")

	fmt.Printf("Message to verify: %s\n", testData)
	fmt.Printf("Verifier DID: %s\n", vid.DID())

	// Mock FIDO2 signature structure (would come from WebAuthn)
	mockSignature := createMockFIDO2Signature(testData)

	// Attempt verification (will fail with mock data, but shows the API)
	err = vid.KeyManager.Verify(testData, mockSignature)
	if err != nil {
		fmt.Printf("Verification result: Failed (expected with mock data)\n")
	} else {
		fmt.Printf("Verification result: Success\n")
	}

	// Demonstrate user verification flag
	err = vid.VerifyFIDO2Signature(testData, mockSignature, true)
	if err != nil {
		fmt.Printf("With user verification: Failed (expected with mock data)\n")
	}

	fmt.Println()
}

func demonstrateFIDO2DiffieHellman() {
	fmt.Println("4. Diffie-Hellman between FIDO2 identities")
	fmt.Println("-------------------------------------------")

	// Create two FIDO2 identities with private keys
	alice := createMockFIDO2Identity("alice")
	bob := createMockFIDO2Identity("bob")

	if alice == nil || bob == nil {
		fmt.Println("Failed to create mock identities")
		return
	}

	// Alice computes shared secret with Bob
	aliceSecret, err := alice.PerformDiffieHellman(bob)
	if err != nil {
		fmt.Printf("Alice DH failed: %v\n", err)
		return
	}

	// Bob computes shared secret with Alice
	bobSecret, err := bob.PerformDiffieHellman(alice)
	if err != nil {
		fmt.Printf("Bob DH failed: %v\n", err)
		return
	}

	fmt.Printf("Alice's DID: %s\n", alice.DID())
	fmt.Printf("Bob's DID: %s\n", bob.DID())

	if aliceSecret != nil && bobSecret != nil {
		fmt.Printf("Shared secret (Alice): %s\n", hex.EncodeToString(aliceSecret)[:32]+"...")
		fmt.Printf("Shared secret (Bob):   %s\n", hex.EncodeToString(bobSecret)[:32]+"...")

		// They should be equal
		if hex.EncodeToString(aliceSecret) == hex.EncodeToString(bobSecret) {
			fmt.Println("✓ Shared secrets match!")
		} else {
			fmt.Println("✗ Shared secrets don't match")
		}
	}

	fmt.Println()
}

func demonstrateInteroperability() {
	fmt.Println("5. TypeScript Interoperability")
	fmt.Println("-------------------------------")

	// This demonstrates how to work with data from the TypeScript implementation
	// The format must match exactly for cross-platform compatibility

	// Example base64-encoded FIDO2 ID from TypeScript
	// This would come from the TypeScript VaultysID.id property
	tsBase64ID := "A4OhdjCh..." // Truncated for example

	fmt.Println("To interoperate with TypeScript:")
	fmt.Println("1. TypeScript exports ID as base64 or hex")
	fmt.Println("2. Go imports using FromIDString()")
	fmt.Printf("   Example: vaultysid.FromIDString(\"%s\", \"base64\", nil)\n", tsBase64ID[:10]+"...")
	fmt.Println()

	// Demonstrate signature format compatibility
	fmt.Println("FIDO2 Signature Format (msgpack):")
	fmt.Println("  {")
	fmt.Println("    s: signature bytes,")
	fmt.Println("    c: client data JSON,")
	fmt.Println("    a: authenticator data")
	fmt.Println("  }")
	fmt.Println()

	// Show COSE key format
	fmt.Println("COSE Key Format (CBOR):")
	fmt.Println("  Ed25519: {1: 1, 3: -8, -2: publicKey}")
	fmt.Println("  P-256:   {1: 2, 3: -7, -1: 1, -2: x, -3: y}")
	fmt.Println()

	// Show transport compatibility
	fmt.Println("Transport Encoding:")
	fmt.Println("  USB: 1, NFC: 2, BLE: 4, Internal: 8, Hybrid: 16, Smart-card: 32")
	fmt.Println("  Multiple transports use bitwise OR")
	fmt.Println()
}

// Helper functions

func createMockCOSEKey() []byte {
	// Create a mock COSE key (Ed25519)
	pubKey := make([]byte, 32)
	// Fill with mock data
	for i := range pubKey {
		pubKey[i] = byte(i * 2)
	}

	coseKey := keymanager.COSEKey{
		1:  1,      // kty: OKP
		3:  -8,     // alg: EdDSA
		-2: pubKey, // x: public key
	}

	// Marshal to CBOR
	coseKeyBytes, err := cbor.Marshal(coseKey)
	if err != nil {
		// Fallback to hardcoded if CBOR fails
		result := []byte{
			0xa3,       // map(3)
			0x01, 0x01, // kty: 1
			0x03, 0x27, // alg: -8 (0x27 = 39 = -8 in CBOR)
			0x20, 0x58, 0x20, // x: bytes(32)
		}
		result = append(result, pubKey...)
		return result
	}

	return coseKeyBytes
}

func createMockEd25519COSEKey() []byte {
	// Create a proper Ed25519 COSE key
	return createMockCOSEKey()
}

func createMockFIDO2Signature(data []byte) []byte {
	// Create a mock FIDO2 signature structure
	// In production, this would come from navigator.credentials.get()

	challenge := base64.RawURLEncoding.EncodeToString(data)
	clientDataJSON := fmt.Sprintf(`{"challenge":"%s","type":"webauthn.get"}`, challenge)

	sig := keymanager.FIDO2Signature{
		S: make([]byte, 64), // Mock Ed25519 signature
		C: []byte(clientDataJSON),
		A: make([]byte, 37), // Mock authenticator data
	}

	// Set some mock authenticator data
	for i := 0; i < 32; i++ {
		sig.A[i] = 0xAB // RP ID hash
	}
	sig.A[32] = 0x01 // Flags: User present

	sigBytes, _ := msgpack.Marshal(sig)
	return sigBytes
}

func createMockFIDO2Identity(name string) *vaultysid.VaultysID {
	// Create a mock FIDO2 identity with a private key
	mockCOSEKey := createMockCOSEKey()
	mockFID := []byte(fmt.Sprintf("fido2-cred-%s", name))

	// Create unique cypher keys for each identity
	mockCypherSecret := make([]byte, 32)
	for i := range mockCypherSecret {
		mockCypherSecret[i] = byte(i) + name[0]
	}

	secretData := keymanager.ExportFIDO2Data{
		V: 1,
		F: mockFID,
		T: 15,
		C: mockCOSEKey,
		E: mockCypherSecret,
	}

	secretBytes, err := msgpack.Marshal(secretData)
	if err != nil {
		return nil
	}

	fullSecret := append([]byte{byte(vaultysid.TypeFIDO2)}, secretBytes...)

	vid, err := vaultysid.FromSecret(fullSecret)
	if err != nil {
		return nil
	}

	return vid
}

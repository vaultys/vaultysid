package vaultysid

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateMachine(t *testing.T) {
	vid, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate machine identity: %v", err)
	}

	if vid.Type != TypeMachine {
		t.Errorf("Expected type %d, got %d", TypeMachine, vid.Type)
	}

	if !vid.IsMachine() {
		t.Error("IsMachine() should return true")
	}

	if vid.GetType() != "machine" {
		t.Errorf("Expected type string 'machine', got %s", vid.GetType())
	}
}

func TestGeneratePerson(t *testing.T) {
	vid, err := GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate person identity: %v", err)
	}

	if vid.Type != TypePerson {
		t.Errorf("Expected type %d, got %d", TypePerson, vid.Type)
	}

	if !vid.IsPerson() {
		t.Error("IsPerson() should return true")
	}
}

func TestGenerateOrganization(t *testing.T) {
	vid, err := GenerateOrganization()
	if err != nil {
		t.Fatalf("Failed to generate organization identity: %v", err)
	}

	if vid.Type != TypeOrganization {
		t.Errorf("Expected type %d, got %d", TypeOrganization, vid.Type)
	}

	if !vid.IsOrganization() {
		t.Error("IsOrganization() should return true")
	}
}

func TestFromEntropy(t *testing.T) {
	// Test with valid entropy
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	vid, err := FromEntropy(entropy, TypeMachine)
	if err != nil {
		t.Fatalf("Failed to create from entropy: %v", err)
	}

	if vid.Type != TypeMachine {
		t.Errorf("Expected type %d, got %d", TypeMachine, vid.Type)
	}

	// Test with invalid entropy size
	badEntropy := make([]byte, 16)
	_, err = FromEntropy(badEntropy, TypeMachine)
	if err == nil {
		t.Error("Should fail with invalid entropy size")
	}
}

func TestIdentitySerialization(t *testing.T) {
	// Generate an identity
	vid1, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// Serialize to bytes
	idBytes := vid1.ToBytes()
	if len(idBytes) != 77 { // 1 byte type + 76 bytes Ed25519Manager
		t.Errorf("Expected ID bytes length 77, got %d", len(idBytes))
	}

	// Deserialize from bytes
	vid2, err := FromID(idBytes, nil)
	if err != nil {
		t.Fatalf("Failed to deserialize ID: %v", err)
	}

	if vid2.Type != vid1.Type {
		t.Errorf("Type mismatch: expected %d, got %d", vid1.Type, vid2.Type)
	}

	// Check public keys match
	if !bytes.Equal(vid1.GetPublicKey(), vid2.GetPublicKey()) {
		t.Error("Public keys don't match")
	}

	if !bytes.Equal(vid1.GetCypherPublicKey(), vid2.GetCypherPublicKey()) {
		t.Error("Cypher public keys don't match")
	}

	// Check capability
	if vid2.GetCapability() != "public" {
		t.Errorf("Expected public capability, got %s", vid2.GetCapability())
	}
}

func TestSecretSerialization(t *testing.T) {
	// Generate an identity
	vid1, err := GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// Get secret
	secret, err := vid1.GetSecret()
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	// Create from secret
	vid2, err := FromSecret(secret)
	if err != nil {
		t.Fatalf("Failed to create from secret: %v", err)
	}

	if vid2.Type != vid1.Type {
		t.Errorf("Type mismatch: expected %d, got %d", vid1.Type, vid2.Type)
	}

	// Should have private capability
	if vid2.GetCapability() != "private" {
		t.Errorf("Expected private capability, got %s", vid2.GetCapability())
	}

	// Should be able to sign
	data := []byte("test message")
	sig1, err := vid1.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign with vid1: %v", err)
	}

	sig2, err := vid2.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign with vid2: %v", err)
	}

	// Signatures should be identical (deterministic)
	if !bytes.Equal(sig1, sig2) {
		t.Error("Signatures don't match")
	}
}

func TestDID(t *testing.T) {
	vid, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	did := vid.DID()

	// Check DID format
	if !strings.HasPrefix(did, "did:vaultys:") {
		t.Errorf("DID should start with 'did:vaultys:', got %s", did)
	}

	// Check DID length (12 + 40 hex chars)
	if len(did) != 52 {
		t.Errorf("DID should be 52 characters, got %d", len(did))
	}

	// Hex part should be valid
	hexPart := did[12:]
	_, err = hex.DecodeString(hexPart)
	if err != nil {
		t.Errorf("DID hex part is invalid: %v", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	vid, err := GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	data := []byte("test message")

	// Sign
	signature, err := vid.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify
	err = vid.Verify(data, signature)
	if err != nil {
		t.Errorf("Failed to verify valid signature: %v", err)
	}

	// Verify with wrong data
	wrongData := []byte("wrong message")
	err = vid.Verify(wrongData, signature)
	if err == nil {
		t.Error("Should fail to verify with wrong data")
	}

	// Verify with wrong signature
	wrongSig := make([]byte, len(signature))
	copy(wrongSig, signature)
	wrongSig[0] ^= 0xFF
	err = vid.Verify(data, wrongSig)
	if err == nil {
		t.Error("Should fail to verify with wrong signature")
	}
}

func TestSignAndVerifyChallenge(t *testing.T) {
	vid, err := GenerateOrganization()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	challenge := []byte("test-challenge-123")

	// Sign challenge
	signature, err := vid.SignChallenge(challenge)
	if err != nil {
		t.Fatalf("Failed to sign challenge: %v", err)
	}

	// Verify challenge
	err = vid.VerifyChallenge(challenge, signature)
	if err != nil {
		t.Errorf("Failed to verify valid challenge: %v", err)
	}

	// Verify with wrong challenge
	wrongChallenge := []byte("wrong-challenge")
	err = vid.VerifyChallenge(wrongChallenge, signature)
	if err == nil {
		t.Error("Should fail to verify with wrong challenge")
	}
}

func TestCertificate(t *testing.T) {
	vid, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// Initially no certificate
	if vid.HasCertificate() {
		t.Error("Should not have certificate initially")
	}

	// Set certificate
	cert := []byte("test-certificate")
	vid.SetCertificate(cert)

	if !vid.HasCertificate() {
		t.Error("Should have certificate after setting")
	}

	// Get certificate
	gotCert := vid.GetCertificate()
	if !bytes.Equal(gotCert, cert) {
		t.Error("Certificate doesn't match")
	}
}

func TestStringEncoding(t *testing.T) {
	vid1, err := GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// Test hex encoding
	hexStr, err := vid1.ToString("hex")
	if err != nil {
		t.Fatalf("Failed to encode to hex: %v", err)
	}

	vid2, err := FromIDString(hexStr, "hex", nil)
	if err != nil {
		t.Fatalf("Failed to decode from hex: %v", err)
	}

	if !bytes.Equal(vid1.GetPublicKey(), vid2.GetPublicKey()) {
		t.Error("Public keys don't match after hex encoding/decoding")
	}

	// Test base64 encoding
	b64Str, err := vid1.ToString("base64")
	if err != nil {
		t.Fatalf("Failed to encode to base64: %v", err)
	}

	vid3, err := FromIDString(b64Str, "base64", nil)
	if err != nil {
		t.Fatalf("Failed to decode from base64: %v", err)
	}

	if !bytes.Equal(vid1.GetPublicKey(), vid3.GetPublicKey()) {
		t.Error("Public keys don't match after base64 encoding/decoding")
	}

	// Test secret string encoding
	secretHex, err := vid1.GetSecretString("hex")
	if err != nil {
		t.Fatalf("Failed to get secret as hex: %v", err)
	}

	vid4, err := FromSecretString(secretHex, "hex")
	if err != nil {
		t.Fatalf("Failed to create from secret hex: %v", err)
	}

	// Should be able to sign with recreated identity
	data := []byte("test")
	sig1, _ := vid1.Sign(data)
	sig4, _ := vid4.Sign(data)
	if !bytes.Equal(sig1, sig4) {
		t.Error("Signatures don't match from secret-recreated identity")
	}
}

func TestEquals(t *testing.T) {
	// Generate two identities with same entropy
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	vid1, err := FromEntropy(entropy, TypeMachine)
	if err != nil {
		t.Fatalf("Failed to create identity 1: %v", err)
	}

	vid2, err := FromEntropy(entropy, TypeMachine)
	if err != nil {
		t.Fatalf("Failed to create identity 2: %v", err)
	}

	if !vid1.Equals(vid2) {
		t.Error("Identities with same entropy should be equal")
	}

	// Different type
	vid3, err := FromEntropy(entropy, TypePerson)
	if err != nil {
		t.Fatalf("Failed to create identity 3: %v", err)
	}

	if vid1.Equals(vid3) {
		t.Error("Identities with different types should not be equal")
	}

	// Different entropy
	entropy2 := make([]byte, 32)
	for i := range entropy2 {
		entropy2[i] = byte(i + 1)
	}

	vid4, err := FromEntropy(entropy2, TypeMachine)
	if err != nil {
		t.Fatalf("Failed to create identity 4: %v", err)
	}

	if vid1.Equals(vid4) {
		t.Error("Identities with different entropy should not be equal")
	}
}

func TestDHIESEncryptDecrypt(t *testing.T) {
	// Create two machine identities
	alice, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate Alice: %v", err)
	}

	bob, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate Bob: %v", err)
	}

	// Test data
	plaintext := []byte("Hello, this is a secret message for Bob!")

	// Alice encrypts for Bob
	ciphertext, err := alice.DHIESEncrypt(plaintext, bob)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Bob decrypts from Alice
	decrypted, err := bob.DHIESDecrypt(ciphertext, alice)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify the decrypted text matches
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match. Got %s, want %s", decrypted, plaintext)
	}

	// Test that wrong recipient can't decrypt
	charlie, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate Charlie: %v", err)
	}

	_, err = charlie.DHIESDecrypt(ciphertext, alice)
	if err == nil {
		t.Error("Charlie should not be able to decrypt message meant for Bob")
	}

	// Test that public-only identity can't encrypt
	publicBob, err := FromID(bob.ToBytes(), nil)
	if err != nil {
		t.Fatalf("Failed to create public Bob: %v", err)
	}

	_, err = publicBob.DHIESEncrypt(plaintext, alice)
	if err == nil {
		t.Error("Public-only identity should not be able to encrypt")
	}

	// Test that public-only identity can't decrypt
	_, err = publicBob.DHIESDecrypt(ciphertext, alice)
	if err == nil {
		t.Error("Public-only identity should not be able to decrypt")
	}

	// Test DHIES with FIDO2 identity (should fail)
	// FIDO2 doesn't support DHIES yet
	t.Run("FIDO2_DHIES_NotSupported", func(t *testing.T) {
		fido2Secret := make([]byte, 65)
		fido2Secret[0] = byte(TypeFIDO2)
		copy(fido2Secret[1:], bytes.Repeat([]byte{0x01}, 64))

		fido2ID, err := FromSecret(fido2Secret)
		if err != nil {
			// It's OK if FIDO2 creation fails in test environment
			t.Skip("FIDO2 identity creation not available in test environment")
		}

		_, err = fido2ID.DHIESEncrypt(plaintext, bob)
		if err == nil {
			t.Error("FIDO2 identity should not support DHIES encryption")
		}
	})
}

func TestClone(t *testing.T) {
	vid1, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	cert := []byte("test-certificate")
	vid1.SetCertificate(cert)

	// Clone
	vid2 := vid1.Clone()

	// Check equality
	if !vid1.Equals(vid2) {
		t.Error("Clone should be equal to original")
	}

	// Check certificate was cloned
	if !bytes.Equal(vid2.GetCertificate(), cert) {
		t.Error("Certificate not cloned properly")
	}

	// Modify clone's certificate
	vid2.SetCertificate([]byte("different"))

	// Original should be unchanged
	if !bytes.Equal(vid1.GetCertificate(), cert) {
		t.Error("Original certificate was modified")
	}
}

func TestCapabilities(t *testing.T) {
	// Test private capability
	vid1, err := GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	if !vid1.IsPrivate() {
		t.Error("Generated identity should be private")
	}

	if vid1.IsPublic() {
		t.Error("Generated identity should not be public")
	}

	// Test public capability
	idBytes := vid1.ToBytes()
	vid2, err := FromID(idBytes, nil)
	if err != nil {
		t.Fatalf("Failed to create from ID: %v", err)
	}

	if vid2.IsPrivate() {
		t.Error("ID-created identity should not be private")
	}

	if !vid2.IsPublic() {
		t.Error("ID-created identity should be public")
	}

	// Public identity cannot sign
	_, err = vid2.Sign([]byte("test"))
	if err == nil {
		t.Error("Public identity should not be able to sign")
	}
}

func TestVersion(t *testing.T) {
	vid, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// Default version should be 1
	if vid.GetVersion() != 1 {
		t.Errorf("Default version should be 1, got %d", vid.GetVersion())
	}

	// Set to version 0
	err = vid.ToVersion(0)
	if err != nil {
		t.Errorf("Failed to set version to 0: %v", err)
	}

	if vid.GetVersion() != 0 {
		t.Errorf("Version should be 0, got %d", vid.GetVersion())
	}

	// Set to version 1
	err = vid.ToVersion(1)
	if err != nil {
		t.Errorf("Failed to set version to 1: %v", err)
	}

	if vid.GetVersion() != 1 {
		t.Errorf("Version should be 1, got %d", vid.GetVersion())
	}

	// Invalid version
	err = vid.ToVersion(2)
	if err == nil {
		t.Error("Should fail with invalid version")
	}
}

func TestString(t *testing.T) {
	vid, err := GenerateOrganization()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	str := vid.String()

	// Should contain type
	if !strings.Contains(str, "organization") {
		t.Error("String should contain identity type")
	}

	// Should contain DID
	if !strings.Contains(str, "did:vaultys:") {
		t.Error("String should contain DID")
	}

	// Should contain capability
	if !strings.Contains(str, "private") {
		t.Error("String should contain capability")
	}
}

func TestChallengeV0Compatibility(t *testing.T) {
	vid, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	challenge := []byte("test-challenge")
	oldID := vid.ToBytes()

	// Sign with v0 protocol
	sig, err := vid.SignChallengeV0(challenge, oldID)
	if err != nil {
		t.Fatalf("Failed to sign v0 challenge: %v", err)
	}

	// Verify with v0 protocol
	err = vid.VerifyChallengeV0(challenge, sig, oldID)
	if err != nil {
		t.Errorf("Failed to verify valid v0 challenge: %v", err)
	}

	// Should fail with wrong oldID
	wrongID := make([]byte, len(oldID))
	copy(wrongID, oldID)
	wrongID[0] ^= 0xFF

	err = vid.VerifyChallengeV0(challenge, sig, wrongID)
	if err == nil {
		t.Error("Should fail to verify v0 challenge with wrong oldID")
	}
}

func TestDiffieHellman(t *testing.T) {
	// Generate two identities
	alice, err := GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate Alice: %v", err)
	}

	bob, err := GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate Bob: %v", err)
	}

	// Compute shared secrets
	aliceShared, err := alice.DiffieHellman(bob.GetCypherPublicKey())
	if err != nil {
		t.Fatalf("Failed to compute Alice's shared secret: %v", err)
	}

	bobShared, err := bob.DiffieHellman(alice.GetCypherPublicKey())
	if err != nil {
		t.Fatalf("Failed to compute Bob's shared secret: %v", err)
	}

	// Shared secrets should match
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("Shared secrets don't match")
	}

	// Public-only identity cannot do DH
	publicBob, err := FromID(bob.ToBytes(), nil)
	if err != nil {
		t.Fatalf("Failed to create public Bob: %v", err)
	}

	_, err = publicBob.DiffieHellman(alice.GetCypherPublicKey())
	if err == nil {
		t.Error("Public identity should not be able to perform DH")
	}
}

func TestHMAC(t *testing.T) {
	vid, err := GenerateMachine()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	message := "test message"
	hmac1, err := vid.HMAC(message)
	if err != nil {
		t.Fatalf("Failed to compute HMAC: %v", err)
	}

	// Same message should produce same HMAC
	hmac2, err := vid.HMAC(message)
	if err != nil {
		t.Fatalf("Failed to compute HMAC again: %v", err)
	}

	if !bytes.Equal(hmac1, hmac2) {
		t.Error("Same message should produce same HMAC")
	}

	// Different message should produce different HMAC
	hmac3, err := vid.HMAC("different message")
	if err != nil {
		t.Fatalf("Failed to compute HMAC for different message: %v", err)
	}

	if bytes.Equal(hmac1, hmac3) {
		t.Error("Different messages should produce different HMACs")
	}

	// Public identity cannot compute HMAC
	publicVid, err := FromID(vid.ToBytes(), nil)
	if err != nil {
		t.Fatalf("Failed to create public identity: %v", err)
	}

	_, err = publicVid.HMAC(message)
	if err == nil {
		t.Error("Public identity should not be able to compute HMAC")
	}
}

func TestIdentityTypeHelpers(t *testing.T) {
	// Generate different types
	machine, _ := GenerateMachine()
	person, _ := GeneratePerson()
	org, _ := GenerateOrganization()

	// Test type helpers
	if !machine.IsMachine() || machine.IsPerson() || machine.IsOrganization() {
		t.Error("Machine type check failed")
	}

	if machine.IsPerson() || !person.IsPerson() || person.IsOrganization() {
		t.Error("Person type check failed")
	}

	if org.IsMachine() || org.IsPerson() || !org.IsOrganization() {
		t.Error("Organization type check failed")
	}

	// Test hardware check (should all be false for Ed25519)
	if machine.IsHardware() || person.IsHardware() || org.IsHardware() {
		t.Error("IsHardware should be false for non-FIDO2 identities")
	}
}

func TestInvalidInputs(t *testing.T) {
	// Empty ID
	_, err := FromID([]byte{}, nil)
	if err == nil {
		t.Error("Should fail with empty ID")
	}

	// Empty secret
	_, err = FromSecret([]byte{})
	if err == nil {
		t.Error("Should fail with empty secret")
	}

	// Invalid identity type
	invalidID := []byte{255} // Invalid type
	invalidID = append(invalidID, make([]byte, 76)...)
	_, err = FromID(invalidID, nil)
	if err == nil {
		t.Error("Should fail with invalid identity type")
	}

	// Invalid encoding
	vid, _ := GenerateMachine()
	_, err = vid.ToString("invalid")
	if err == nil {
		t.Error("Should fail with invalid encoding")
	}

	// Invalid entropy size
	_, err = FromEntropy([]byte("short"), TypeMachine)
	if err == nil {
		t.Error("Should fail with short entropy")
	}
}

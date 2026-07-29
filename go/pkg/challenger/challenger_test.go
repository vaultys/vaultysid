package challenger

import (
	"bytes"
	"testing"
	"time"

	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

func TestChallenger_BasicFlow(t *testing.T) {
	// Create two identities
	alice, err := vaultysid.GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate Alice: %v", err)
	}

	bob, err := vaultysid.GeneratePerson()
	if err != nil {
		t.Fatalf("Failed to generate Bob: %v", err)
	}

	// Create challengers
	aliceChallenger := NewChallenger(alice, nil)
	bobChallenger := NewChallenger(bob, nil)

	// Alice initiates
	initChallenge, err := aliceChallenger.Init("test-protocol", "test-service")
	if err != nil {
		t.Fatalf("Failed to init challenge: %v", err)
	}

	if initChallenge.State != StateInit {
		t.Errorf("Expected state INIT, got %d", initChallenge.State)
	}

	// Bob responds with step1
	step1Challenge, err := bobChallenger.Step1(initChallenge)
	if err != nil {
		t.Fatalf("Failed step1: %v", err)
	}

	if step1Challenge.State != StateStep1 {
		t.Errorf("Expected state STEP1, got %d", step1Challenge.State)
	}

	// Alice completes with step2
	completeChallenge, err := aliceChallenger.Step2(step1Challenge)
	if err != nil {
		t.Fatalf("Failed step2: %v", err)
	}

	if completeChallenge.State != StateComplete {
		t.Errorf("Expected state COMPLETE, got %d", completeChallenge.State)
	}

	// Bob finalizes
	err = bobChallenger.Finalize(completeChallenge)
	if err != nil {
		t.Fatalf("Failed to finalize: %v", err)
	}

	// Both should be complete
	if !aliceChallenger.IsComplete() {
		t.Error("Alice should be complete")
	}

	if !bobChallenger.IsComplete() {
		t.Error("Bob should be complete")
	}

	// Check remote IDs
	if !bytes.Equal(aliceChallenger.GetRemoteID(), bob.ToBytes()) {
		t.Error("Alice's remote ID should be Bob")
	}

	if !bytes.Equal(bobChallenger.GetRemoteID(), alice.ToBytes()) {
		t.Error("Bob's remote ID should be Alice")
	}
}

func TestChallenger_Process(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	aliceChallenger := NewChallenger(alice, nil)
	bobChallenger := NewChallenger(bob, nil)

	// Alice initiates
	challenge, _ := aliceChallenger.Init("protocol", "service")

	// Bob processes and responds
	challenge, err := bobChallenger.Process(challenge)
	if err != nil {
		t.Fatalf("Bob failed to process init: %v", err)
	}

	// Alice processes and completes
	challenge, err = aliceChallenger.Process(challenge)
	if err != nil {
		t.Fatalf("Alice failed to process step1: %v", err)
	}

	// Bob processes completion
	_, err = bobChallenger.Process(challenge)
	if err != nil {
		t.Fatalf("Bob failed to process complete: %v", err)
	}

	// Both should be complete
	if !aliceChallenger.IsComplete() || !bobChallenger.IsComplete() {
		t.Error("Both challengers should be complete")
	}
}

func TestChallenger_Serialization(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	aliceChallenger := NewChallenger(alice, nil)
	bobChallenger := NewChallenger(bob, nil)

	// Create init challenge
	initChallenge, _ := aliceChallenger.Init("protocol", "service")

	// Serialize and deserialize
	serialized, err := Serialize(initChallenge)
	if err != nil {
		t.Fatalf("Failed to serialize: %v", err)
	}

	deserialized, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize: %v", err)
	}

	if deserialized.State != StateInit {
		t.Errorf("Expected state INIT, got %d", deserialized.State)
	}

	// Process with deserialized challenge
	step1, err := bobChallenger.Step1(deserialized)
	if err != nil {
		t.Fatalf("Failed to process deserialized challenge: %v", err)
	}

	if step1.State != StateStep1 {
		t.Error("Step1 should produce STEP1 state")
	}
}

func TestChallenger_Metadata(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()

	challenger := NewChallenger(alice, nil)

	// Set metadata
	challenger.SetMetadata("key1", "value1")
	challenger.SetMetadata("key2", "value2")

	// Get metadata
	val, ok := challenger.GetMetadata("key1")
	if !ok || val != "value1" {
		t.Error("Failed to get metadata key1")
	}

	val, ok = challenger.GetMetadata("key2")
	if !ok || val != "value2" {
		t.Error("Failed to get metadata key2")
	}

	// Non-existent key
	_, ok = challenger.GetMetadata("nonexistent")
	if ok {
		t.Error("Should not find nonexistent key")
	}
}

func TestChallenger_Timestamp(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	// Create challenger with short time window
	opts := &ChallengerOptions{
		Version:    ProtocolV1,
		TimeWindow: 5 * time.Second,
	}
	bobChallenger := NewChallenger(bob, opts)

	// Create init challenge with old timestamp
	initChallenge := &Challenge{
		Version:   ProtocolV1,
		Protocol:  "test",
		Service:   "service",
		Timestamp: time.Now().UnixMilli() - 10000, // 10 seconds ago
		PK1:       alice.ToBytes(),
		Nonce:     make([]byte, 16),
		State:     StateInit,
	}

	// Should fail due to timestamp
	_, err := bobChallenger.Step1(initChallenge)
	if err == nil {
		t.Error("Should fail with old timestamp")
	}

	// Create challenge with valid timestamp
	initChallenge.Timestamp = time.Now().UnixMilli()
	_, err = bobChallenger.Step1(initChallenge)
	if err != nil {
		t.Errorf("Should succeed with valid timestamp: %v", err)
	}
}

func TestChallenger_Reset(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	challenger := NewChallenger(alice, nil)

	// Init challenge
	_, err := challenger.Init("protocol", "service")
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	if challenger.GetState() != StateInit {
		t.Error("Should be in INIT state")
	}

	// Reset
	challenger.Reset()

	if challenger.GetState() != StateUninitialized {
		t.Error("Should be uninitialized after reset")
	}

	// Should be able to init again
	_, err = challenger.Init("protocol2", "service2")
	if err != nil {
		t.Fatalf("Failed to init after reset: %v", err)
	}
}

func TestChallenger_InvalidStates(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	aliceChallenger := NewChallenger(alice, nil)
	bobChallenger := NewChallenger(bob, nil)

	// Try to init twice
	_, _ = aliceChallenger.Init("protocol", "service")
	_, err := aliceChallenger.Init("protocol", "service")
	if err == nil {
		t.Error("Should not be able to init twice")
	}

	// Try step1 without receiving init
	fakeStep1 := &Challenge{
		State: StateStep1,
	}
	_, err = aliceChallenger.Step2(fakeStep1)
	if err == nil {
		t.Error("Should fail to process step1 without proper init")
	}

	// Try to process invalid state
	invalidChallenge := &Challenge{
		State: 999,
	}
	_, err = bobChallenger.Process(invalidChallenge)
	if err == nil {
		t.Error("Should fail with invalid state")
	}
}

func TestChallenger_WrongIdentity(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()
	charlie, _ := vaultysid.GeneratePerson()

	aliceChallenger := NewChallenger(alice, nil)
	charlieChallenger := NewChallenger(charlie, nil)

	// Alice initiates
	initChallenge, _ := aliceChallenger.Init("protocol", "service")

	// Bob responds
	bobChallenger := NewChallenger(bob, nil)
	step1Challenge, _ := bobChallenger.Step1(initChallenge)

	// Charlie tries to complete (should fail)
	_, err := charlieChallenger.Step2(step1Challenge)
	if err == nil {
		t.Error("Charlie should not be able to complete Alice's challenge")
	}
}

func TestChallenger_NonceValidation(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	aliceChallenger := NewChallenger(alice, nil)
	bobChallenger := NewChallenger(bob, nil)

	// Create init with wrong nonce size
	badInit := &Challenge{
		Version:   ProtocolV1,
		Protocol:  "test",
		Service:   "service",
		Timestamp: time.Now().UnixMilli(),
		PK1:       alice.ToBytes(),
		Nonce:     make([]byte, 8), // Wrong size
		State:     StateInit,
	}

	_, err := bobChallenger.Step1(badInit)
	if err == nil {
		t.Error("Should fail with wrong nonce size")
	}

	// Create step1 with wrong nonce size
	initChallenge, _ := aliceChallenger.Init("protocol", "service")
	step1Challenge, _ := bobChallenger.Step1(initChallenge)

	// Tamper with nonce
	step1Challenge.Nonce = make([]byte, 16) // Wrong size for step1

	_, err = aliceChallenger.Step2(step1Challenge)
	if err == nil {
		t.Error("Should fail with tampered nonce")
	}
}

func TestChallenger_SignatureVerification(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	aliceChallenger := NewChallenger(alice, nil)
	bobChallenger := NewChallenger(bob, nil)

	// Normal flow
	initChallenge, _ := aliceChallenger.Init("protocol", "service")
	step1Challenge, _ := bobChallenger.Step1(initChallenge)

	// Tamper with signature
	step1Challenge.Sign2[0] ^= 0xFF

	_, err := aliceChallenger.Step2(step1Challenge)
	if err == nil {
		t.Error("Should fail with tampered signature")
	}
}

func TestChallenge_Helpers(t *testing.T) {
	challenge := &Challenge{
		PK1:   []byte{1, 2, 3},
		PK2:   []byte{4, 5, 6},
		Sign1: []byte{7, 8, 9},
		Sign2: []byte{10, 11, 12},
		State: StateComplete,
	}

	if !challenge.HasPK1() {
		t.Error("Should have PK1")
	}
	if !challenge.HasPK2() {
		t.Error("Should have PK2")
	}
	if !challenge.HasSign1() {
		t.Error("Should have Sign1")
	}
	if !challenge.HasSign2() {
		t.Error("Should have Sign2")
	}
	if !challenge.IsComplete() {
		t.Error("Should be complete")
	}

	// Test other states
	challenge.State = StateInit
	if !challenge.IsInit() {
		t.Error("Should be init")
	}

	challenge.State = StateStep1
	if !challenge.IsStep1() {
		t.Error("Should be step1")
	}

	challenge.State = StateError
	if !challenge.IsError() {
		t.Error("Should be error")
	}
}

func TestChallenge_Clone(t *testing.T) {
	original := &Challenge{
		Version:   ProtocolV1,
		Protocol:  "test",
		Service:   "service",
		Timestamp: 12345,
		PK1:       []byte{1, 2, 3},
		PK2:       []byte{4, 5, 6},
		Nonce:     []byte{7, 8, 9},
		Sign1:     []byte{10, 11, 12},
		Sign2:     []byte{13, 14, 15},
		State:     StateComplete,
		Error:     "test error",
		Metadata: ChallengeMetadata{
			PK1: map[string]string{"key1": "value1"},
			PK2: map[string]string{"key2": "value2"},
		},
	}

	clone := original.Clone()

	// Check equality
	if clone.Version != original.Version ||
		clone.Protocol != original.Protocol ||
		clone.Service != original.Service ||
		clone.Timestamp != original.Timestamp ||
		clone.State != original.State ||
		clone.Error != original.Error {
		t.Error("Basic fields not cloned correctly")
	}

	// Check byte slices are cloned (not same reference)
	if &clone.PK1[0] == &original.PK1[0] {
		t.Error("PK1 not deep cloned")
	}
	if !bytes.Equal(clone.PK1, original.PK1) {
		t.Error("PK1 values don't match")
	}

	// Check metadata is cloned
	if clone.Metadata.PK1["key1"] != "value1" {
		t.Error("Metadata not cloned correctly")
	}

	// Modify clone shouldn't affect original
	clone.PK1[0] = 99
	if original.PK1[0] == 99 {
		t.Error("Modifying clone affected original")
	}
}

func TestChallenger_GetRemoteVaultysID(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	aliceChallenger := NewChallenger(alice, nil)
	bobChallenger := NewChallenger(bob, nil)

	// Before protocol, should fail
	_, err := aliceChallenger.GetRemoteVaultysID()
	if err == nil {
		t.Error("Should fail before protocol completion")
	}

	// Complete protocol
	initChallenge, _ := aliceChallenger.Init("protocol", "service")
	step1Challenge, _ := bobChallenger.Step1(initChallenge)
	completeChallenge, _ := aliceChallenger.Step2(step1Challenge)
	_ = bobChallenger.Finalize(completeChallenge)

	// Now should work
	remoteAlice, err := bobChallenger.GetRemoteVaultysID()
	if err != nil {
		t.Fatalf("Failed to get remote VaultysID: %v", err)
	}

	if !bytes.Equal(remoteAlice.ToBytes(), alice.ToBytes()) {
		t.Error("Remote VaultysID doesn't match Alice")
	}

	remoteBob, err := aliceChallenger.GetRemoteVaultysID()
	if err != nil {
		t.Fatalf("Failed to get remote VaultysID: %v", err)
	}

	if !bytes.Equal(remoteBob.ToBytes(), bob.ToBytes()) {
		t.Error("Remote VaultysID doesn't match Bob")
	}
}

func TestChallenger_V0Compatibility(t *testing.T) {
	t.Skip("V0 compatibility needs more work - skipping for now")

	// Create identities with v0
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	// Set to version 0
	alice.ToVersion(0)
	bob.ToVersion(0)

	opts := &ChallengerOptions{
		Version:    ProtocolV0,
		TimeWindow: 60 * time.Second,
	}

	aliceChallenger := NewChallenger(alice, opts)
	bobChallenger := NewChallenger(bob, opts)

	// Run protocol
	initChallenge, err := aliceChallenger.Init("protocol", "service")
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	if initChallenge.Version != ProtocolV0 {
		t.Errorf("Expected v0, got %d", initChallenge.Version)
	}

	step1Challenge, err := bobChallenger.Step1(initChallenge)
	if err != nil {
		t.Fatalf("Failed step1: %v", err)
	}

	completeChallenge, err := aliceChallenger.Step2(step1Challenge)
	if err != nil {
		t.Fatalf("Failed step2: %v", err)
	}

	err = bobChallenger.Finalize(completeChallenge)
	if err != nil {
		t.Fatalf("Failed to finalize: %v", err)
	}

	if !aliceChallenger.IsComplete() || !bobChallenger.IsComplete() {
		t.Error("Both should be complete")
	}
}

// TestChallenger_AcceptFullHandshake drives a complete handshake purely through
// Accept()/Serialize(), simulating what two peers exchange over a real transport.
// Regression test for Accept() always treating incoming bytes as StateInit because
// State (msgpack:"-") was read via a raw msgpack.Unmarshal instead of Deserialize's
// field-based state inference.
func TestChallenger_AcceptFullHandshake(t *testing.T) {
	alice, _ := vaultysid.GeneratePerson()
	bob, _ := vaultysid.GeneratePerson()

	aliceChallenger := NewChallenger(alice, nil)
	bobChallenger := NewChallenger(bob, nil)

	initChallenge, err := aliceChallenger.Init("protocol", "service")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	initBytes, err := Serialize(initChallenge)
	if err != nil {
		t.Fatalf("Serialize init failed: %v", err)
	}

	step1Challenge, err := bobChallenger.Accept(initBytes)
	if err != nil {
		t.Fatalf("Bob Accept(init) failed: %v", err)
	}
	if step1Challenge.State != StateStep1 {
		t.Fatalf("expected STEP1 response, got state %d", step1Challenge.State)
	}
	step1Bytes, err := Serialize(step1Challenge)
	if err != nil {
		t.Fatalf("Serialize step1 failed: %v", err)
	}

	completeChallenge, err := aliceChallenger.Accept(step1Bytes)
	if err != nil {
		t.Fatalf("Alice Accept(step1) failed: %v", err)
	}
	if completeChallenge.State != StateComplete {
		t.Fatalf("expected COMPLETE response, got state %d", completeChallenge.State)
	}
	completeBytes, err := Serialize(completeChallenge)
	if err != nil {
		t.Fatalf("Serialize complete failed: %v", err)
	}

	resp, err := bobChallenger.Accept(completeBytes)
	if err != nil {
		t.Fatalf("Bob Accept(complete) failed: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response on finalize, got %+v", resp)
	}
	if !bobChallenger.IsComplete() {
		t.Error("Bob challenger should be complete")
	}
}

func TestDeserialize_InvalidData(t *testing.T) {
	// Test with invalid msgpack
	_, err := Deserialize([]byte("invalid"))
	if err == nil {
		t.Error("Should fail with invalid data")
	}

	// Test with missing fields (empty challenge)
	serialized, _ := Serialize(&Challenge{
		Version: ProtocolV1,
		State:   StateInit,
	})

	deserialized, err := Deserialize(serialized)
	if err == nil || deserialized.State != StateError {
		t.Error("Should be in error state with missing fields")
	}
}

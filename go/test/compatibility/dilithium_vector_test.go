package compatibility

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

type dilithiumVector struct {
	Inputs struct {
		Protocol    string `json:"protocol"`
		Service     string `json:"service"`
		TimestampMs uint64 `json:"timestampMs"`
		Nonce1Hex   string `json:"nonce1Hex"`
		Nonce2Hex   string `json:"nonce2Hex"`
	} `json:"inputs"`
	Identities struct {
		Alice struct {
			IDHex string `json:"idHex"`
			DID   string `json:"did"`
		} `json:"alice"`
		Bob struct {
			IDHex string `json:"idHex"`
			DID   string `json:"did"`
		} `json:"bob"`
	} `json:"identities"`
	Steps []struct {
		Name             string `json:"name"`
		State            int    `json:"state"`
		UnsignedBytesHex string `json:"unsignedBytesHex"`
		Sign1Hex         string `json:"sign1Hex"`
		Sign2Hex         string `json:"sign2Hex"`
		WireBytesHex     string `json:"wireBytesHex"`
	} `json:"steps"`
}

func loadDilithiumVector(t *testing.T) *dilithiumVector {
	paths := []string{
		"testdata/challenger-handshake-dilithium.json", // self-contained copy, always available
		"../../../rfc/vectors/challenger-handshake-dilithium.json",
		"../../rfc/vectors/challenger-handshake-dilithium.json",
	}
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if data == nil {
		t.Skipf("Dilithium reference vector not found (tried %v): %v", paths, err)
	}
	var v dilithiumVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("failed to parse dilithium vector: %v", err)
	}
	return &v
}

func stepByName(v *dilithiumVector, name string) *struct {
	Name             string `json:"name"`
	State            int    `json:"state"`
	UnsignedBytesHex string `json:"unsignedBytesHex"`
	Sign1Hex         string `json:"sign1Hex"`
	Sign2Hex         string `json:"sign2Hex"`
	WireBytesHex     string `json:"wireBytesHex"`
} {
	for i := range v.Steps {
		if v.Steps[i].Name == name {
			return &v.Steps[i]
		}
	}
	return nil
}

// TestDilithiumChallengerVector_MatchesTypeScript reproduces the exact
// Dilithium (post-quantum) Challenger handshake recorded in
// rfc/vectors/challenger-handshake-dilithium.json -- generated
// independently by the TypeScript reference implementation -- using only
// public data from the vector (ids and recorded signatures, not
// TypeScript-generated secrets), and checks that Go's own
// Serialize/SerializeUnsigned byte output for the same logical challenge
// matches TypeScript's recorded output exactly, and that Go can verify
// TypeScript's recorded sign1/sign2 signatures via the full VaultysID
// stack (i.e. including the SHA-256("VAULTYS_SIGN" || data) wrapping,
// not just the raw KeyManager.Verify checked in
// pkg/keymanager/dilithium_test.go).
//
// This is the Dilithium counterpart to the Ed25519 cross-validation done
// via typescript/test/interops/verify-rfc-vectors.ts (which validates
// from the TypeScript side); this test validates the same vector from
// the Go side, so both directions are covered.
func TestDilithiumChallengerVector_MatchesTypeScript(t *testing.T) {
	v := loadDilithiumVector(t)

	aliceID, err := hex.DecodeString(v.Identities.Alice.IDHex)
	if err != nil {
		t.Fatal(err)
	}
	bobID, err := hex.DecodeString(v.Identities.Bob.IDHex)
	if err != nil {
		t.Fatal(err)
	}

	alice, err := vaultysid.FromID(aliceID, nil)
	if err != nil {
		t.Fatalf("failed to parse alice's Dilithium id (Go dispatch may not be routing 2638-byte ids to Dilithium): %v", err)
	}
	bob, err := vaultysid.FromID(bobID, nil)
	if err != nil {
		t.Fatalf("failed to parse bob's Dilithium id: %v", err)
	}

	if alice.DID() != v.Identities.Alice.DID {
		t.Errorf("alice DID mismatch: got %s want %s", alice.DID(), v.Identities.Alice.DID)
	}
	if bob.DID() != v.Identities.Bob.DID {
		t.Errorf("bob DID mismatch: got %s want %s", bob.DID(), v.Identities.Bob.DID)
	}

	nonce1, _ := hex.DecodeString(v.Inputs.Nonce1Hex)
	nonce2, _ := hex.DecodeString(v.Inputs.Nonce2Hex)
	combinedNonce := append(append([]byte{}, nonce1...), nonce2...)

	// --- INIT ---
	initStep := stepByName(v, "init")
	initChallenge := &challenger.Challenge{
		Version:   1,
		Protocol:  v.Inputs.Protocol,
		Service:   v.Inputs.Service,
		Timestamp: v.Inputs.TimestampMs,
		PK1:       alice.ToBytes(),
		Nonce:     nonce1,
		State:     0,
	}
	initBytes, err := challenger.Serialize(initChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(initBytes) != initStep.WireBytesHex {
		t.Errorf("INIT wire bytes mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(initBytes), initStep.WireBytesHex)
	}

	// --- unsigned bytes (shared by STEP1 and COMPLETE) ---
	step1Step := stepByName(v, "step1")
	unsignedChallenge := &challenger.Challenge{
		Version:   1,
		Protocol:  v.Inputs.Protocol,
		Service:   v.Inputs.Service,
		Timestamp: v.Inputs.TimestampMs,
		PK1:       alice.ToBytes(),
		PK2:       bob.ToBytes(),
		Nonce:     combinedNonce,
	}
	unsignedBytes, err := challenger.SerializeUnsigned(unsignedChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(unsignedBytes) != step1Step.UnsignedBytesHex {
		t.Errorf("unsigned bytes mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(unsignedBytes), step1Step.UnsignedBytesHex)
	}

	// --- verify TypeScript's recorded sign2 via the full VaultysID stack ---
	sign2, err := hex.DecodeString(step1Step.Sign2Hex)
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.VerifyChallenge(unsignedBytes, sign2); err != nil {
		t.Errorf("failed to verify TypeScript-produced sign2 via VaultysID.VerifyChallenge: %v", err)
	}

	step1Challenge := &challenger.Challenge{
		Version:   1,
		Protocol:  v.Inputs.Protocol,
		Service:   v.Inputs.Service,
		Timestamp: v.Inputs.TimestampMs,
		PK1:       alice.ToBytes(),
		PK2:       bob.ToBytes(),
		Nonce:     combinedNonce,
		Sign2:     sign2,
		State:     1,
	}
	step1Bytes, err := challenger.Serialize(step1Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(step1Bytes) != step1Step.WireBytesHex {
		t.Errorf("STEP1 wire bytes mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(step1Bytes), step1Step.WireBytesHex)
	}

	// --- verify TypeScript's recorded sign1 and build COMPLETE ---
	completeStep := stepByName(v, "complete")
	sign1, err := hex.DecodeString(completeStep.Sign1Hex)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.VerifyChallenge(unsignedBytes, sign1); err != nil {
		t.Errorf("failed to verify TypeScript-produced sign1 via VaultysID.VerifyChallenge: %v", err)
	}

	completeChallenge := &challenger.Challenge{
		Version:   1,
		Protocol:  v.Inputs.Protocol,
		Service:   v.Inputs.Service,
		Timestamp: v.Inputs.TimestampMs,
		PK1:       alice.ToBytes(),
		PK2:       bob.ToBytes(),
		Nonce:     combinedNonce,
		Sign1:     sign1,
		Sign2:     sign2,
		State:     2,
	}
	completeBytes, err := challenger.Serialize(completeChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(completeBytes) != completeStep.WireBytesHex {
		t.Errorf("COMPLETE wire bytes mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(completeBytes), completeStep.WireBytesHex)
	}
}

// TestVaultysID_DilithiumSignAndVerifyRoundTrip exercises the full
// VaultysID.SignChallenge/VerifyChallenge stack (dispatch + Dilithium +
// SIGN_INCIPIT wrapping) independently of any TypeScript vector, using
// freshly generated Go-only identities.
func TestVaultysID_DilithiumSignAndVerifyRoundTrip(t *testing.T) {
	alice, err := vaultysid.FromEntropyAlg(make([]byte, 32), vaultysid.TypePerson, "dilithium")
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello dilithium")
	sig, err := alice.SignChallenge(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.VerifyChallenge(data, sig); err != nil {
		t.Errorf("self sign/verify failed: %v", err)
	}

	// Round-trip through id/secret and re-verify with the reconstructed
	// public-only identity.
	pub, err := vaultysid.FromID(alice.ToBytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.VerifyChallenge(data, sig); err != nil {
		t.Errorf("verify via reconstructed public id failed: %v", err)
	}

	secret, err := alice.GetSecret()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := vaultysid.FromSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := restored.SignChallenge(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.VerifyChallenge(data, sig2); err != nil {
		t.Errorf("verify signature from secret-restored identity failed: %v", err)
	}
}

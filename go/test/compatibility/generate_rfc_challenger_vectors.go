//go:build ignore
// +build ignore

// Run this file with: go run generate_rfc_challenger_vectors.go
// It regenerates rfc/vectors/challenger-handshake-ed25519.json.

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fixedBytes(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

type vectorOut struct {
	Description string `json:"description"`
	Generated   string `json:"generated"`
	Inputs      struct {
		AliceEntropyHex string `json:"aliceEntropyHex"`
		BobEntropyHex   string `json:"bobEntropyHex"`
		Protocol        string `json:"protocol"`
		Service         string `json:"service"`
		TimestampMs     uint64 `json:"timestampMs"`
		Nonce1Hex       string `json:"nonce1Hex"`
		Nonce2Hex       string `json:"nonce2Hex"`
	} `json:"inputs"`
	Identities struct {
		Alice struct {
			SecretHex string `json:"secretHex"`
			IDHex     string `json:"idHex"`
			DID       string `json:"did"`
		} `json:"alice"`
		Bob struct {
			SecretHex string `json:"secretHex"`
			IDHex     string `json:"idHex"`
			DID       string `json:"did"`
		} `json:"bob"`
	} `json:"identities"`
	Steps []struct {
		Name             string `json:"name"`
		State            int    `json:"state"`
		UnsignedBytesHex string `json:"unsignedBytesHex,omitempty"`
		Sign1Hex         string `json:"sign1Hex,omitempty"`
		Sign2Hex         string `json:"sign2Hex,omitempty"`
		WireBytesHex     string `json:"wireBytesHex"`
		VerifiedByPeer   bool   `json:"verifiedByPeer"`
	} `json:"steps"`
	EncodingNotes []string `json:"encodingNotes"`
}

func main() {
	aliceEntropy := fixedBytes(0x00, 32)
	bobEntropy := fixedBytes(0x20, 32)

	alice, err := vaultysid.FromEntropy(aliceEntropy, vaultysid.TypePerson)
	must(err)
	bob, err := vaultysid.FromEntropy(bobEntropy, vaultysid.TypePerson)
	must(err)

	protocol := "vaultys.wot"
	service := "auth"
	var timestamp uint64 = 1735689600000 // 2025-01-01T00:00:00.000Z
	nonce1 := fixedBytes(0x00, 16)
	nonce2 := fixedBytes(0x10, 16)
	combinedNonce := append(append([]byte{}, nonce1...), nonce2...)

	out := vectorOut{
		Description: "Deterministic reference vectors for the Vaultys handcheck (Challenger) protocol, generated from the Go implementation and cross-checked against the same VaultysID keys/signatures used to verify them. Fixed entropy/nonces/timestamp are used so every implementation can reproduce byte-identical output.",
		Generated:   "vaultys/vaultysid go/pkg/challenger, generated for RFC/PROTOCOL.md",
	}
	out.Inputs.AliceEntropyHex = hex.EncodeToString(aliceEntropy)
	out.Inputs.BobEntropyHex = hex.EncodeToString(bobEntropy)
	out.Inputs.Protocol = protocol
	out.Inputs.Service = service
	out.Inputs.TimestampMs = timestamp
	out.Inputs.Nonce1Hex = hex.EncodeToString(nonce1)
	out.Inputs.Nonce2Hex = hex.EncodeToString(nonce2)

	aliceSecret, err := alice.GetSecret()
	must(err)
	bobSecret, err := bob.GetSecret()
	must(err)
	out.Identities.Alice.SecretHex = hex.EncodeToString(aliceSecret)
	out.Identities.Alice.IDHex = hex.EncodeToString(alice.ToBytes())
	out.Identities.Alice.DID = alice.DID()
	out.Identities.Bob.SecretHex = hex.EncodeToString(bobSecret)
	out.Identities.Bob.IDHex = hex.EncodeToString(bob.ToBytes())
	out.Identities.Bob.DID = bob.DID()

	// --- INIT ---
	initChallenge := &challenger.Challenge{
		Version:  1,
		Protocol: protocol,
		Service:  service,
		// Timestamp/PK1/Nonce set below
		State: 0, // StateInit
	}
	initChallenge.Timestamp = timestamp
	initChallenge.PK1 = alice.ToBytes()
	initChallenge.Nonce = nonce1
	initBytes, err := challenger.Serialize(initChallenge)
	must(err)

	// Deserialize confirms this is a well-formed, self-consistent INIT message.
	desInit, err := challenger.Deserialize(initBytes)
	must(err)

	// --- STEP1 (Bob signs) ---
	unsignedForStep1AndComplete := &challenger.Challenge{
		Version:  1,
		Protocol: protocol,
		Service:  service,
		Timestamp: timestamp,
		PK1:      alice.ToBytes(),
		PK2:      bob.ToBytes(),
		Nonce:    combinedNonce,
	}
	unsignedBytes, err := challenger.SerializeUnsigned(unsignedForStep1AndComplete)
	must(err)

	sign2, err := bob.SignChallenge(unsignedBytes)
	must(err)
	bobPub, err := vaultysid.FromID(bob.ToBytes(), nil)
	must(err)
	must(bobPub.VerifyChallenge(unsignedBytes, sign2)) // sanity: a peer holding only bob's public ID can verify bob's sign2

	step1Challenge := &challenger.Challenge{
		Version:  1,
		Protocol: protocol,
		Service:  service,
		Timestamp: timestamp,
		PK1:      alice.ToBytes(),
		PK2:      bob.ToBytes(),
		Nonce:    combinedNonce,
		Sign2:    sign2,
		State:    1, // StateStep1
	}
	step1Bytes, err := challenger.Serialize(step1Challenge)
	must(err)
	desStep1, err := challenger.Deserialize(step1Bytes)
	must(err)

	// --- COMPLETE (Alice signs sign1 over the same unsigned bytes) ---
	sign1, err := alice.SignChallenge(unsignedBytes)
	must(err)
	alicePub, err := vaultysid.FromID(alice.ToBytes(), nil)
	must(err)
	must(alicePub.VerifyChallenge(unsignedBytes, sign1)) // sanity: a peer holding only alice's public ID can verify alice's sign1

	completeChallenge := &challenger.Challenge{
		Version:  1,
		Protocol: protocol,
		Service:  service,
		Timestamp: timestamp,
		PK1:      alice.ToBytes(),
		PK2:      bob.ToBytes(),
		Nonce:    combinedNonce,
		Sign1:    sign1,
		Sign2:    sign2,
		State:    2, // StateComplete
	}
	completeBytes, err := challenger.Serialize(completeChallenge)
	must(err)
	desComplete, err := challenger.Deserialize(completeBytes)
	must(err)

	addStep := func(name string, state int, unsigned, s1, s2, wire []byte, verified bool) {
		var step struct {
			Name             string `json:"name"`
			State            int    `json:"state"`
			UnsignedBytesHex string `json:"unsignedBytesHex,omitempty"`
			Sign1Hex         string `json:"sign1Hex,omitempty"`
			Sign2Hex         string `json:"sign2Hex,omitempty"`
			WireBytesHex     string `json:"wireBytesHex"`
			VerifiedByPeer   bool   `json:"verifiedByPeer"`
		}
		step.Name = name
		step.State = state
		if unsigned != nil {
			step.UnsignedBytesHex = hex.EncodeToString(unsigned)
		}
		if s1 != nil {
			step.Sign1Hex = hex.EncodeToString(s1)
		}
		if s2 != nil {
			step.Sign2Hex = hex.EncodeToString(s2)
		}
		step.WireBytesHex = hex.EncodeToString(wire)
		step.VerifiedByPeer = verified
		out.Steps = append(out.Steps, step)
	}

	addStep("init", desInit.State, nil, nil, nil, initBytes, true)
	addStep("step1", desStep1.State, unsignedBytes, nil, sign2, step1Bytes, true)
	addStep("complete", desComplete.State, unsignedBytes, sign1, sign2, completeBytes, true)

	out.EncodingNotes = []string{
		"All integer fields (version, timestamp) MUST use msgpack's minimal-width representation (e.g. Go's UseCompactInts / equivalent), not a fixed-width encoding: version=0 as a bare 0x00 fixint, never 0xcc 0x00.",
		"timestamp MUST be encoded as an unsigned integer type; encoding it as signed produces different wire bytes for the same non-negative value (0xd3 vs 0xcf at 64-bit width) and breaks byte-exact signature verification.",
		"Field order and field presence per state MUST match exactly: INIT = {version, protocol, service, timestamp, pk1, nonce, metadata}; STEP1 adds pk2 (after pk1) and sign2 (after nonce), no sign1; COMPLETE adds sign1 before sign2. metadata is always present, even if empty ({}).",
		"The 'unsigned bytes' used for both sign1 and sign2 are identical once pk1/pk2/nonce are both final (STEP1 and COMPLETE sign over the same payload) -- only the *wire* envelope differs (STEP1 omits sign1, COMPLETE includes it).",
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}

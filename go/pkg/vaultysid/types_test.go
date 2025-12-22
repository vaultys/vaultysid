package vaultysid

import (
	"bytes"
	"strings"
	"testing"
)

func TestVaultysID_Basic(t *testing.T) {
	km := &mockKeyManager{
		publicKey: []byte{1, 2, 3, 4},
		toBytes:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
		version:   1,
	}

	vid := &VaultysID{
		Type:       TypePerson,
		KeyManager: km,
	}

	// Test DID
	did := vid.DID()
	if !strings.HasPrefix(did, "did:vaultys:") {
		t.Errorf("DID should start with 'did:vaultys:', got %s", did)
	}

	// Test ToBytes
	b := vid.ToBytes()
	if b[0] != 1 { // TypePerson = 1
		t.Errorf("First byte should be 1, got %d", b[0])
	}
	if !bytes.Equal(b[1:], km.toBytes) {
		t.Error("ToBytes should include key manager bytes")
	}

	// Test Sign
	data := []byte("test")
	sig, err := vid.Sign(data)
	if err != nil || sig == nil {
		t.Error("Sign failed")
	}

	// Test Verify
	if err := vid.Verify(data, sig); err != nil {
		t.Error("Verify failed")
	}
}

func TestIdentityType_String(t *testing.T) {
	tests := []struct {
		typ      IdentityType
		expected string
	}{
		{TypeMachine, "machine"},
		{TypePerson, "person"},
		{TypeOrganization, "organization"},
		{TypeFIDO2, "fido2"},
		{TypeFIDO2PRF, "fido2prf"},
		{IdentityType(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.typ.String()
		if got != tt.expected {
			t.Errorf("IdentityType(%d).String() = %s, want %s", tt.typ, got, tt.expected)
		}
	}
}

func TestParseIdentityType(t *testing.T) {
	tests := []struct {
		input    string
		expected IdentityType
		wantErr  bool
	}{
		{"machine", TypeMachine, false},
		{"person", TypePerson, false},
		{"organization", TypeOrganization, false},
		{"fido2", TypeFIDO2, false},
		{"fido2prf", TypeFIDO2PRF, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		got, err := ParseIdentityType(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseIdentityType(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("ParseIdentityType(%s) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestIdentityType_IsValid(t *testing.T) {
	tests := []struct {
		typ     IdentityType
		isValid bool
	}{
		{TypeMachine, true},
		{TypePerson, true},
		{TypeOrganization, true},
		{TypeFIDO2, true},
		{TypeFIDO2PRF, true},
		{IdentityType(5), false},
		{IdentityType(99), false},
	}

	for _, tt := range tests {
		got := tt.typ.IsValid()
		if got != tt.isValid {
			t.Errorf("IdentityType(%d).IsValid() = %v, want %v", tt.typ, got, tt.isValid)
		}
	}
}

func TestIdentityType_IsHardware(t *testing.T) {
	tests := []struct {
		typ        IdentityType
		isHardware bool
	}{
		{TypeMachine, false},
		{TypePerson, false},
		{TypeOrganization, false},
		{TypeFIDO2, true},
		{TypeFIDO2PRF, true},
	}

	for _, tt := range tests {
		got := tt.typ.IsHardware()
		if got != tt.isHardware {
			t.Errorf("IdentityType(%d).IsHardware() = %v, want %v", tt.typ, got, tt.isHardware)
		}
	}
}

type mockKeyManager struct {
	publicKey []byte
	toBytes   []byte
	version   int
}

func (m *mockKeyManager) Sign(data []byte) ([]byte, error) {
	return []byte("sig"), nil
}

func (m *mockKeyManager) Verify(data, signature []byte) error {
	return nil
}

func (m *mockKeyManager) GetPublicKey() []byte {
	return m.publicKey
}

func (m *mockKeyManager) GetCypherPublicKey() []byte {
	return []byte{5, 6, 7, 8}
}

func (m *mockKeyManager) DiffieHellman(peerPublicKey []byte) ([]byte, error) {
	return []byte("shared"), nil
}

func (m *mockKeyManager) HMAC(message string) ([]byte, error) {
	return []byte("hmac"), nil
}

func (m *mockKeyManager) GetCapability() string {
	return "private"
}

func (m *mockKeyManager) ToBytes() []byte {
	return m.toBytes
}

func (m *mockKeyManager) GetSecret() ([]byte, error) {
	return []byte("secret"), nil
}

func (m *mockKeyManager) GetAuthType() string {
	return "Ed25519VerificationKey2020"
}

func (m *mockKeyManager) GetEncType() string {
	return "X25519KeyAgreementKey2019"
}

func (m *mockKeyManager) GetVersion() int {
	return m.version
}

func (m *mockKeyManager) SetVersion(version int) error {
	m.version = version
	return nil
}

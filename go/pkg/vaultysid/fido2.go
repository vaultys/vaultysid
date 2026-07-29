package vaultysid

import (
	"fmt"

	"github.com/vaultys/vaultysid/go/pkg/keymanager"
)

// FIDO2FromSecret creates a VaultysID from a FIDO2Manager secret
func FIDO2FromSecret(secret []byte) (*VaultysID, error) {
	km, err := keymanager.FIDO2FromSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create FIDO2 key manager from secret: %w", err)
	}

	return &VaultysID{
		Type:       TypeFIDO2,
		KeyManager: km,
	}, nil
}

// FIDO2FromID creates a VaultysID from a FIDO2Manager public ID
func FIDO2FromID(id []byte) (*VaultysID, error) {
	km, err := keymanager.FIDO2FromID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to create FIDO2 key manager from ID: %w", err)
	}

	return &VaultysID{
		Type:       TypeFIDO2,
		KeyManager: km,
	}, nil
}

// IsFIDO2 returns true if this is a FIDO2-backed identity
func (v *VaultysID) IsFIDO2() bool {
	return v.Type == TypeFIDO2 || v.Type == TypeFIDO2PRF
}

// VerifyFIDO2Signature verifies a FIDO2 signature with optional user verification
func (v *VaultysID) VerifyFIDO2Signature(data, signature []byte, userVerification bool) error {
	if !v.IsFIDO2() {
		return fmt.Errorf("not a FIDO2 identity")
	}

	// Type assert to FIDO2Manager
	if fido2km, ok := v.KeyManager.(*keymanager.FIDO2Manager); ok {
		return fido2km.VerifyWithUserVerification(data, signature, userVerification)
	}

	// Fall back to regular verify if type assertion fails
	return v.KeyManager.Verify(data, signature)
}

// GetFIDO2Transports returns the authenticator transports if this is a FIDO2 identity
func (v *VaultysID) GetFIDO2Transports() ([]string, error) {
	if !v.IsFIDO2() {
		return nil, fmt.Errorf("not a FIDO2 identity")
	}

	if fido2km, ok := v.KeyManager.(*keymanager.FIDO2Manager); ok {
		return fido2km.GetTransports(), nil
	}

	return nil, fmt.Errorf("invalid FIDO2 key manager")
}

// GetFIDO2CredentialID returns the FIDO2 credential ID if available
func (v *VaultysID) GetFIDO2CredentialID() ([]byte, error) {
	if !v.IsFIDO2() {
		return nil, fmt.Errorf("not a FIDO2 identity")
	}

	if fido2km, ok := v.KeyManager.(*keymanager.FIDO2Manager); ok {
		if fido2km.FID != nil {
			return fido2km.FID, nil
		}
		return nil, fmt.Errorf("no credential ID available (public-only key)")
	}

	return nil, fmt.Errorf("invalid FIDO2 key manager")
}

// GetCOSEKey returns the COSE public key if this is a FIDO2 identity
func (v *VaultysID) GetCOSEKey() ([]byte, error) {
	if !v.IsFIDO2() {
		return nil, fmt.Errorf("not a FIDO2 identity")
	}

	if fido2km, ok := v.KeyManager.(*keymanager.FIDO2Manager); ok {
		return fido2km.CKey, nil
	}

	return nil, fmt.Errorf("invalid FIDO2 key manager")
}

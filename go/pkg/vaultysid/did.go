package vaultysid

import (
	"encoding/base64"
	"fmt"
)

// DIDDocument represents a W3C DID Document
type DIDDocument struct {
	Context        []string             `json:"@context"`
	ID             string               `json:"id"`
	Authentication []VerificationMethod `json:"authentication"`
	KeyAgreement   []VerificationMethod `json:"keyAgreement"`
}

// VerificationMethod represents a verification method in a DID document
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// DIDDocument returns the W3C DID Document for this identity
func (v *VaultysID) DIDDocument() *DIDDocument {
	did := v.DID()

	// Create the DID document
	doc := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
			"https://w3id.org/security/suites/x25519-2019/v1",
		},
		ID: did,
	}

	// Add authentication method
	authPubKey := v.KeyManager.GetPublicKey()
	authType := v.KeyManager.GetAuthType()

	// Encode public key with multibase prefix (0x00 for base58btc is not standard, using 'z' for base58btc)
	// For simplicity, we'll use base64url with 'u' prefix
	authKeyMultibase := "u" + base64.RawURLEncoding.EncodeToString(authPubKey)

	authMethod := VerificationMethod{
		ID:                 fmt.Sprintf("%s#auth", did),
		Type:               authType,
		Controller:         did,
		PublicKeyMultibase: authKeyMultibase,
	}
	doc.Authentication = []VerificationMethod{authMethod}

	// Add key agreement method
	encPubKey := v.KeyManager.GetCypherPublicKey()
	encType := v.KeyManager.GetEncType()

	// Encode public key with multibase
	encKeyMultibase := "u" + base64.RawURLEncoding.EncodeToString(encPubKey)

	keyAgrMethod := VerificationMethod{
		ID:                 fmt.Sprintf("%s#enc", did),
		Type:               encType,
		Controller:         did,
		PublicKeyMultibase: encKeyMultibase,
	}
	doc.KeyAgreement = []VerificationMethod{keyAgrMethod}

	return doc
}

// ResolveDID resolves a DID to its document
func ResolveDID(did string) (*DIDDocument, error) {
	// This is a placeholder for DID resolution
	// In a real implementation, this would resolve the DID from a registry or network
	return nil, fmt.Errorf("DID resolution not implemented")
}

// UpdateDIDDocument updates the DID document for this identity
func (v *VaultysID) UpdateDIDDocument(doc *DIDDocument) error {
	// This is a placeholder for DID document updates
	// In a real implementation, this would update the DID document in a registry
	return fmt.Errorf("DID document updates not implemented")
}

// VerifyDIDDocument verifies that a DID document matches this identity
func (v *VaultysID) VerifyDIDDocument(doc *DIDDocument) error {
	expectedDID := v.DID()
	if doc.ID != expectedDID {
		return fmt.Errorf("DID mismatch: expected %s, got %s", expectedDID, doc.ID)
	}

	// Verify authentication method
	if len(doc.Authentication) == 0 {
		return fmt.Errorf("no authentication methods in DID document")
	}

	authMethod := doc.Authentication[0]
	if authMethod.Controller != expectedDID {
		return fmt.Errorf("authentication controller mismatch")
	}

	if authMethod.Type != v.KeyManager.GetAuthType() {
		return fmt.Errorf("authentication type mismatch: expected %s, got %s",
			v.KeyManager.GetAuthType(), authMethod.Type)
	}

	// Verify key agreement method
	if len(doc.KeyAgreement) == 0 {
		return fmt.Errorf("no key agreement methods in DID document")
	}

	keyAgrMethod := doc.KeyAgreement[0]
	if keyAgrMethod.Controller != expectedDID {
		return fmt.Errorf("key agreement controller mismatch")
	}

	if keyAgrMethod.Type != v.KeyManager.GetEncType() {
		return fmt.Errorf("key agreement type mismatch: expected %s, got %s",
			v.KeyManager.GetEncType(), keyAgrMethod.Type)
	}

	return nil
}

// GetAuthenticationKey returns the authentication public key from the DID document
func (d *DIDDocument) GetAuthenticationKey() ([]byte, error) {
	if len(d.Authentication) == 0 {
		return nil, fmt.Errorf("no authentication methods")
	}

	method := d.Authentication[0]

	// Decode multibase public key
	if len(method.PublicKeyMultibase) < 2 {
		return nil, fmt.Errorf("invalid multibase key")
	}

	// Check prefix and decode
	prefix := method.PublicKeyMultibase[0]
	encoded := method.PublicKeyMultibase[1:]

	switch prefix {
	case 'u': // base64url
		return base64.RawURLEncoding.DecodeString(encoded)
	case 'z': // base58btc
		// Would need base58 library for this
		return nil, fmt.Errorf("base58btc not implemented")
	default:
		return nil, fmt.Errorf("unsupported multibase prefix: %c", prefix)
	}
}

// GetKeyAgreementKey returns the key agreement public key from the DID document
func (d *DIDDocument) GetKeyAgreementKey() ([]byte, error) {
	if len(d.KeyAgreement) == 0 {
		return nil, fmt.Errorf("no key agreement methods")
	}

	method := d.KeyAgreement[0]

	// Decode multibase public key
	if len(method.PublicKeyMultibase) < 2 {
		return nil, fmt.Errorf("invalid multibase key")
	}

	// Check prefix and decode
	prefix := method.PublicKeyMultibase[0]
	encoded := method.PublicKeyMultibase[1:]

	switch prefix {
	case 'u': // base64url
		return base64.RawURLEncoding.DecodeString(encoded)
	case 'z': // base58btc
		// Would need base58 library for this
		return nil, fmt.Errorf("base58btc not implemented")
	default:
		return nil, fmt.Errorf("unsupported multibase prefix: %c", prefix)
	}
}

// Equal checks if two DID documents are equal
func (d *DIDDocument) Equal(other *DIDDocument) bool {
	if d == nil || other == nil {
		return d == other
	}

	if d.ID != other.ID {
		return false
	}

	if len(d.Authentication) != len(other.Authentication) {
		return false
	}

	for i, method := range d.Authentication {
		otherMethod := other.Authentication[i]
		if method.ID != otherMethod.ID ||
			method.Type != otherMethod.Type ||
			method.Controller != otherMethod.Controller ||
			method.PublicKeyMultibase != otherMethod.PublicKeyMultibase {
			return false
		}
	}

	if len(d.KeyAgreement) != len(other.KeyAgreement) {
		return false
	}

	for i, method := range d.KeyAgreement {
		otherMethod := other.KeyAgreement[i]
		if method.ID != otherMethod.ID ||
			method.Type != otherMethod.Type ||
			method.Controller != otherMethod.Controller ||
			method.PublicKeyMultibase != otherMethod.PublicKeyMultibase {
			return false
		}
	}

	return true
}

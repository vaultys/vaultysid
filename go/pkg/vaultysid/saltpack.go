package vaultysid

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/keybase/saltpack"
	"github.com/keybase/saltpack/basic"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
)

// Saltpack encryption, byte-compatible with the TypeScript library
// (CypherManager.encrypt / signcrypt / decrypt over @vaultys/saltpack):
//
//   - saltpack version 2.0, encryption mode, Base62 armor, no brand;
//   - recipients are named in the header (not hidden), by their X25519 key;
//   - Encrypt uses an anonymous sender (the ephemeral key), Signcrypt uses the
//     identity's own X25519 key as the sender — despite the name, TypeScript's
//     signcrypt is saltpack *encryption* with a known sender, not saltpack's
//     separate signcryption mode, and so is this;
//   - Decrypt accepts any sender; DecryptFrom also checks it is the expected one.

// ErrUnexpectedSender is returned by DecryptFrom when the message was
// encrypted by someone other than the expected sender, or anonymously.
var ErrUnexpectedSender = errors.New("saltpack: message was not sent by the expected sender")

const saltpackBrand = ""

func boxPublicKey(id *VaultysID) (basic.PublicKey, error) {
	var key basic.PublicKey
	if id == nil || id.KeyManager == nil {
		return key, fmt.Errorf("nil identity")
	}
	raw := id.KeyManager.GetCypherPublicKey()
	if len(raw) != len(key.RawBoxKey) {
		return key, fmt.Errorf("identity has no X25519 public key")
	}
	copy(key.RawBoxKey[:], raw)
	return key, nil
}

func (v *VaultysID) boxSecretKey() (basic.SecretKey, error) {
	provider, ok := v.KeyManager.(keymanager.CypherSecretProvider)
	if !ok {
		return basic.SecretKey{}, fmt.Errorf("this identity type cannot decrypt")
	}
	secret, err := provider.GetCypherSecretKey()
	if err != nil {
		return basic.SecretKey{}, err
	}
	pub, err := boxPublicKey(v)
	if err != nil {
		return basic.SecretKey{}, err
	}
	var sec [32]byte
	copy(sec[:], secret)
	raw := [32]byte(pub.RawBoxKey)
	return basic.NewSecretKey(&raw, &sec), nil
}

func boxPublicKeys(recipients []*VaultysID) ([]saltpack.BoxPublicKey, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipient")
	}
	keys := make([]saltpack.BoxPublicKey, 0, len(recipients))
	for i, recipient := range recipients {
		key, err := boxPublicKey(recipient)
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// Encrypt encrypts plaintext for recipients with an anonymous sender — the
// counterpart of the static VaultysId.encrypt in TypeScript. It needs no secret,
// so it is also available as the package-level Encrypt.
func (v *VaultysID) Encrypt(plaintext string, recipients []*VaultysID) (string, error) {
	return Encrypt(plaintext, recipients)
}

// Encrypt encrypts plaintext for recipients with an anonymous sender.
func Encrypt(plaintext string, recipients []*VaultysID) (string, error) {
	receivers, err := boxPublicKeys(recipients)
	if err != nil {
		return "", err
	}
	return saltpack.EncryptArmor62Seal(saltpack.Version2(), []byte(plaintext), nil, receivers, saltpackBrand)
}

// Signcrypt encrypts plaintext for recipients with this identity as the
// authenticated sender, so a recipient can check who wrote it (DecryptFrom).
func (v *VaultysID) Signcrypt(plaintext string, recipients []*VaultysID) (string, error) {
	sender, err := v.boxSecretKey()
	if err != nil {
		return "", err
	}
	receivers, err := boxPublicKeys(recipients)
	if err != nil {
		return "", err
	}
	return saltpack.EncryptArmor62Seal(saltpack.Version2(), []byte(plaintext), sender, receivers, saltpackBrand)
}

// Decrypt opens a message encrypted for this identity, whoever sent it.
func (v *VaultysID) Decrypt(ciphertext string) (string, error) {
	plaintext, _, err := v.open(ciphertext)
	return plaintext, err
}

// DecryptFrom opens a message encrypted for this identity and checks it was
// sent by sender — the TypeScript decrypt(message, senderId).
func (v *VaultysID) DecryptFrom(ciphertext string, sender *VaultysID) (string, error) {
	expected, err := boxPublicKey(sender)
	if err != nil {
		return "", fmt.Errorf("sender: %w", err)
	}
	plaintext, info, err := v.open(ciphertext)
	if err != nil {
		return "", err
	}
	if info.SenderIsAnon || info.SenderKey == nil || !bytes.Equal(info.SenderKey.ToKID(), expected.ToKID()) {
		return "", ErrUnexpectedSender
	}
	return plaintext, nil
}

func (v *VaultysID) open(ciphertext string) (string, *saltpack.MessageKeyInfo, error) {
	secret, err := v.boxSecretKey()
	if err != nil {
		return "", nil, err
	}
	keyring := basic.NewKeyring()
	keyring.ImportBoxKey((*[32]byte)(secret.GetRawPublicKey()), secret.GetRawSecretKey())
	info, plaintext, _, err := saltpack.Dearmor62DecryptOpen(saltpack.SingleVersionValidator(saltpack.Version2()), ciphertext, keyring)
	if err != nil {
		return "", nil, fmt.Errorf("saltpack: %w", err)
	}
	return string(plaintext), info, nil
}

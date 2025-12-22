package keymanager

import (
	"bytes"
	"testing"
)

func TestDHIES_EncryptDecrypt(t *testing.T) {
	alice, _ := GenerateInternal()
	bob, _ := GenerateInternal()

	dhiesAlice, err := NewDHIES(alice)
	if err != nil {
		t.Fatal(err)
	}

	dhiesBob, err := NewDHIES(bob)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secret message")

	// Alice encrypts for Bob
	ciphertext, err := dhiesAlice.Encrypt(bob.GetCypherPublicKey(), plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts
	decrypted, err := dhiesBob.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted doesn't match plaintext")
	}
}

func TestDHIES_PublicKeyManager(t *testing.T) {
	km, _ := GenerateInternal()
	publicKm, _ := FromIDInternal(km.ToBytes())

	// Should fail with public-only manager
	_, err := NewDHIES(publicKm)
	if err == nil {
		t.Error("Should fail with public-only manager")
	}
}

func TestDHIES_LargeMessage(t *testing.T) {
	km, _ := GenerateInternal()
	dhies, _ := NewDHIES(km)

	// Test with larger message
	plaintext := bytes.Repeat([]byte("x"), 1000)
	recipient, _ := GenerateInternal()

	ciphertext, err := dhies.Encrypt(recipient.GetCypherPublicKey(), plaintext)
	if err != nil {
		t.Fatal(err)
	}

	dhiesRecipient, _ := NewDHIES(recipient)
	decrypted, err := dhiesRecipient.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Large message decryption failed")
	}
}

func TestDHIES_CrossEncryption(t *testing.T) {
	alice, _ := GenerateInternal()
	bob, _ := GenerateInternal()

	// Test that Alice and Bob can encrypt for each other
	message := []byte("test")

	// Alice encrypts for Bob
	dhiesAlice, _ := NewDHIES(alice)
	encrypted1, _ := dhiesAlice.Encrypt(bob.GetCypherPublicKey(), message)

	// Bob encrypts for Alice
	dhiesBob, _ := NewDHIES(bob)
	encrypted2, _ := dhiesBob.Encrypt(alice.GetCypherPublicKey(), message)

	// Bob decrypts Alice's message
	decrypted1, _ := dhiesBob.Decrypt(encrypted1)
	if !bytes.Equal(decrypted1, message) {
		t.Error("Bob couldn't decrypt Alice's message")
	}

	// Alice decrypts Bob's message
	decrypted2, _ := dhiesAlice.Decrypt(encrypted2)
	if !bytes.Equal(decrypted2, message) {
		t.Error("Alice couldn't decrypt Bob's message")
	}
}

func TestDHIES_InvalidCiphertext(t *testing.T) {
	km, _ := GenerateInternal()
	dhies, _ := NewDHIES(km)

	// Test with invalid ciphertext
	invalidCiphertext := []byte("invalid")
	_, err := dhies.Decrypt(invalidCiphertext)
	if err == nil {
		t.Error("Should fail with invalid ciphertext")
	}

	// Test with empty ciphertext
	_, err = dhies.Decrypt([]byte{})
	if err == nil {
		t.Error("Should fail with empty ciphertext")
	}

	// Test with truncated ciphertext
	validRecipient, _ := GenerateInternal()
	validCiphertext, _ := dhies.Encrypt(validRecipient.GetCypherPublicKey(), []byte("test"))

	truncated := validCiphertext[:len(validCiphertext)/2]
	dhiesRecipient, _ := NewDHIES(validRecipient)
	_, err = dhiesRecipient.Decrypt(truncated)
	if err == nil {
		t.Error("Should fail with truncated ciphertext")
	}
}

func TestDHIES_EmptyMessage(t *testing.T) {
	alice, _ := GenerateInternal()
	bob, _ := GenerateInternal()

	dhiesAlice, _ := NewDHIES(alice)
	dhiesBob, _ := NewDHIES(bob)

	// Test with empty message
	emptyMessage := []byte{}

	ciphertext, err := dhiesAlice.Encrypt(bob.GetCypherPublicKey(), emptyMessage)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := dhiesBob.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(emptyMessage, decrypted) {
		t.Error("Empty message encryption/decryption failed")
	}
}

package compatibility

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// TypeScript → Go: every ciphertext made by VaultysId.encrypt / signcrypt in
// TypeScript (typescript/test/interops/generate-saltpack-vectors.ts) must open
// in Go, for every recipient, with the right sender, and for nobody else.

type saltpackVectors struct {
	Identities map[string]struct {
		Secret  string `json:"secret"`
		Alg     string `json:"alg"`
		Version int    `json:"version"`
		ID      string `json:"id"`
	} `json:"identities"`
	Cases []struct {
		Name            string   `json:"name"`
		Plaintext       *string  `json:"plaintext"`
		PlaintextSha256 string   `json:"plaintextSha256"`
		Recipients      []string `json:"recipients"`
		Sender          *string  `json:"sender"`
		Ciphertext      string   `json:"ciphertext"`
		// Set when TypeScript itself cannot open the message: Go must refuse it too.
		ExpectError string `json:"expectError"`
	} `json:"cases"`
}

func loadSaltpackIdentities(t *testing.T, v saltpackVectors) map[string]*vaultysid.VaultysID {
	t.Helper()
	ids := map[string]*vaultysid.VaultysID{}
	for name, exported := range v.Identities {
		id, err := vaultysid.FromSecretString(exported.Secret, "base64")
		if err != nil {
			t.Fatalf("identity %s: %v", name, err)
		}
		if err := id.ToVersion(exported.Version); err != nil {
			t.Fatalf("identity %s: version: %v", name, err)
		}
		// Same public identity as TypeScript, or the keys are not the same keys.
		if got := hex.EncodeToString(id.ID()); got != exported.ID {
			t.Fatalf("identity %s: id mismatch\n go %s\n ts %s", name, got, exported.ID)
		}
		ids[name] = id
	}
	return ids
}

func TestSaltpackTypeScriptVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "saltpack-ts-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v saltpackVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	ids := loadSaltpackIdentities(t, v)

	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			matches := func(t *testing.T, got string) {
				t.Helper()
				if c.Plaintext != nil {
					if got != *c.Plaintext {
						t.Fatalf("plaintext mismatch: %q", truncate(got))
					}
					return
				}
				sum := sha256.Sum256([]byte(got))
				if hex.EncodeToString(sum[:]) != c.PlaintextSha256 {
					t.Fatalf("plaintext hash mismatch (%d bytes)", len(got))
				}
				// And it is the generator's text, so both sides agree on what was tested.
				if got != largePlaintext() {
					t.Fatalf("large plaintext differs from the generator's")
				}
			}

			if c.ExpectError != "" {
				for _, name := range c.Recipients {
					if got, err := ids[name].Decrypt(c.Ciphertext); err == nil {
						t.Fatalf("%s opened a message TypeScript refuses (%s): %q", name, c.ExpectError, got)
					}
				}
				return
			}

			for _, name := range c.Recipients {
				recipient := ids[name]
				got, err := recipient.Decrypt(c.Ciphertext)
				if err != nil {
					t.Fatalf("%s cannot decrypt: %v", name, err)
				}
				matches(t, got)

				if c.Sender != nil {
					got, err := recipient.DecryptFrom(c.Ciphertext, ids[*c.Sender])
					if err != nil {
						t.Fatalf("%s: DecryptFrom(%s): %v", name, *c.Sender, err)
					}
					matches(t, got)
				}
				// Whoever the message claims, another identity is not its sender.
				for other := range ids {
					if c.Sender != nil && other == *c.Sender {
						continue
					}
					if _, err := recipient.DecryptFrom(c.Ciphertext, ids[other]); !errors.Is(err, vaultysid.ErrUnexpectedSender) {
						t.Fatalf("%s: DecryptFrom(%s) should fail with ErrUnexpectedSender, got %v", name, other, err)
					}
				}
			}

			// Not a recipient: cannot open it.
			for name, id := range ids {
				if contains(c.Recipients, name) {
					continue
				}
				if _, err := id.Decrypt(c.Ciphertext); err == nil {
					t.Fatalf("%s is not a recipient but decrypted the message", name)
				}
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// largePlaintext rebuilds the generator's chunk-boundary text exactly:
// line.repeat(ceil(size / byteLength(line))).slice(0, size), where slice counts
// UTF-16 code units (every character of the line is in the BMP, so runes).
func largePlaintext() string {
	line := "VaultysHub stored password · chunk boundary test · "
	size := 1024*1024 + 4096
	reps := (size + len(line) - 1) / len(line) // len is the UTF-8 byte length, like Buffer.byteLength
	runes := []rune(strings.Repeat(line, reps))
	if len(runes) > size {
		runes = runes[:size]
	}
	return string(runes)
}

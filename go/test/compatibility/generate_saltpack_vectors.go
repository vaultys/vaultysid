//go:build ignore
// +build ignore

// Saltpack vectors for the TypeScript implementation: ciphertexts produced by
// the Go Encrypt / Signcrypt, which typescript/test/interops/go-saltpack-compatibility.test.ts
// must open. Regenerate with (from go/test/compatibility):
//
//	go run generate_saltpack_vectors.go
//
// Same identities (same seeds) as the TypeScript generator, so each side also
// checks that both derive the same public identity from the same entropy.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func entropy(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

type exported struct {
	Secret  string `json:"secret"`
	Alg     string `json:"alg"`
	Version int    `json:"version"`
	ID      string `json:"id"`
}

type vectorCase struct {
	Name            string   `json:"name"`
	Plaintext       *string  `json:"plaintext,omitempty"`
	PlaintextSha256 string   `json:"plaintextSha256,omitempty"`
	Recipients      []string `json:"recipients"`
	Sender          *string  `json:"sender"`
	Ciphertext      string   `json:"ciphertext"`
}

func main() {
	type spec struct {
		seed    byte
		idType  vaultysid.IdentityType
		alg     string
		version int
	}
	specs := map[string]spec{
		"server":   {0x10, vaultysid.TypeMachine, "ed25519", 1},
		"serverV0": {0x30, vaultysid.TypeMachine, "ed25519", 0},
		"alice":    {0x50, vaultysid.TypePerson, "ed25519", 1},
		"bob":      {0x70, vaultysid.TypePerson, "ed25519", 1},
		"carolPQ":  {0x90, vaultysid.TypePerson, "dilithium", 1},
	}
	ids := map[string]*vaultysid.VaultysID{}
	identities := map[string]exported{}
	for name, s := range specs {
		id := must(vaultysid.FromEntropyAlg(entropy(s.seed), s.idType, s.alg))
		if err := id.ToVersion(s.version); err != nil {
			panic(err)
		}
		ids[name] = id
		identities[name] = exported{Secret: must(id.GetSecretString("base64")), Alg: s.alg, Version: s.version, ID: hex.EncodeToString(id.ID())}
	}

	var cases []vectorCase
	add := func(name, plaintext string, recipients []string, sender string, storeHash bool) {
		to := make([]*vaultysid.VaultysID, len(recipients))
		for i, r := range recipients {
			to[i] = ids[r]
		}
		var ciphertext string
		var from *string
		if sender == "" {
			ciphertext = must(vaultysid.Encrypt(plaintext, to))
		} else {
			ciphertext = must(ids[sender].Signcrypt(plaintext, to))
			from = &sender
		}
		c := vectorCase{Name: name, Recipients: recipients, Sender: from, Ciphertext: ciphertext}
		if storeHash {
			sum := sha256.Sum256([]byte(plaintext))
			c.PlaintextSha256 = hex.EncodeToString(sum[:])
		} else {
			p := plaintext
			c.Plaintext = &p
		}
		cases = append(cases, c)
	}

	add("anonymous, one recipient (stored app password)", "s3cr3t-P@ssw0rd!", []string{"server"}, "", false)
	add("anonymous, legacy v0 recipient", "legacy organization password", []string{"serverV0"}, "", false)
	add("anonymous, three recipients incl. post-quantum", "shared with a folder", []string{"server", "bob", "carolPQ"}, "", false)
	add("known sender, two recipients", "signcrypted note", []string{"bob", "carolPQ"}, "alice", false)
	add("known post-quantum sender", "from a PQ identity", []string{"server"}, "carolPQ", false)
	add("unicode", "mot de passe — ünïcödé 🔐 密码", []string{"server"}, "", false)
	// Go writes the spec's single empty final packet, so this one must open in TypeScript.
	add("empty", "", []string{"server"}, "", false)
	add("larger than one chunk", largePlaintext(), []string{"server"}, "alice", true)

	out := map[string]any{
		"description": "VaultysId saltpack ciphertexts produced by Go, to be opened by TypeScript",
		"generatedBy": "go/test/compatibility/generate_saltpack_vectors.go",
		"identities":  identities,
		"cases":       cases,
	}
	data := must(json.MarshalIndent(out, "", "  "))
	path := "testdata/saltpack-go-vectors.json"
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %d cases to %s\n", len(cases), path)
}

// Same text as the TypeScript generator (see saltpack_ts_test.go).
func largePlaintext() string {
	line := "VaultysHub stored password · chunk boundary test · "
	size := 1024*1024 + 4096
	reps := (size + len(line) - 1) / len(line)
	runes := []rune(strings.Repeat(line, reps))
	if len(runes) > size {
		runes = runes[:size]
	}
	return string(runes)
}

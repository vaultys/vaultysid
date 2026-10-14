package compatibility

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// TestSecurityV2Vectors consumes the cross-language security-v2 vectors
// produced by the TypeScript reference (testdata/security-v2-vectors.json):
// a handshake certificate (sign1/sign2 under VAULTYS_HANDSHAKE_V1), a DHIES
// v2 ciphertext to decrypt as the recipient, and a VAULTYS_RAW signature.
//
// The exact JSON shape was not fixed when this test was written, so field
// lookup is tolerant (several plausible names, searched recursively within
// each section). Sections whose fields cannot be found are skipped, not
// failed.
// TODO(security-v2): tighten to the final schema once the TS vectors land.
func TestSecurityV2Vectors(t *testing.T) {
	path := filepath.Join("testdata", "security-v2-vectors.json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("testdata/security-v2-vectors.json not present yet (produced by the TypeScript team)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("invalid vectors JSON: %v", err)
	}

	t.Run("handshake", func(t *testing.T) {
		sec := section(root, "handshake", "challenger", "challenge", "certificate")
		if sec == nil {
			t.Skip("no handshake section")
		}
		cert := findBytes(sec, "certificateHex", "certificate", "completeHex", "completeWireHex", "certificateBase64")
		if cert == nil {
			if step := findStep(sec, "complete"); step != nil {
				cert = findBytes(step, "wireBytesHex", "wireHex", "messageHex", "bytesHex")
			}
		}
		if cert == nil {
			t.Skip("no certificate field found")
		}
		ch, err := challenger.VerifyCertificate(cert)
		if err != nil {
			t.Fatalf("TS handshake certificate rejected: %v", err)
		}
		unsigned, _ := challenger.SerializeUnsigned(ch)
		if want := findBytes(sec, "unsignedHex", "unsignedBytesHex"); want != nil && hex.EncodeToString(want) != hex.EncodeToString(unsigned) {
			t.Fatalf("unsigned bytes differ from TS:\n got %x\nwant %x", unsigned, want)
		}
		id1, _ := vaultysid.FromID(ch.PK1, nil)
		id2, _ := vaultysid.FromID(ch.PK2, nil)
		if id1.VerifyHandshake(unsigned, ch.Sign1) != nil || id2.VerifyHandshake(unsigned, ch.Sign2) != nil {
			t.Fatal("VerifyHandshake failed on TS signatures")
		}
	})

	t.Run("dhies", func(t *testing.T) {
		sec := section(root, "dhies", "dhiesV2", "dhies_v2", "encryption")
		if sec == nil {
			t.Skip("no dhies section")
		}
		ct := findBytes(sec, "ciphertextHex", "ciphertext", "messageHex", "outputHex")
		recipientSecret := findBytes(sec, "recipientSecretHex", "bobSecretHex", "BSecretHex", "secretBHex", "bSecretHex")
		senderID := findBytes(sec, "senderIdHex", "aliceIdHex", "AIdHex", "idAHex", "aIdHex")
		if ct == nil || recipientSecret == nil || senderID == nil {
			t.Skip("dhies fields not found")
		}
		b, err := vaultysid.FromSecret(recipientSecret)
		if err != nil {
			t.Fatalf("recipient secret: %v", err)
		}
		a, err := vaultysid.FromID(senderID, nil)
		if err != nil {
			t.Fatalf("sender id: %v", err)
		}
		pt, err := b.DHIESDecrypt(ct, a)
		if err != nil {
			t.Fatalf("DHIES v2 decrypt of TS ciphertext failed: %v", err)
		}
		if want := findString(sec, "plaintext", "plaintextUtf8"); want != "" && string(pt) != want {
			if wantHex := findBytes(sec, "plaintextHex"); wantHex == nil || string(wantHex) != string(pt) {
				t.Fatalf("plaintext mismatch: %q", pt)
			}
		}
	})

	t.Run("raw", func(t *testing.T) {
		sec := section(root, "raw", "rawSign", "vaultysRaw", "sign", "signature")
		if sec == nil {
			t.Skip("no raw signature section")
		}
		id := findBytes(sec, "idHex", "id", "signerIdHex")
		data := findBytes(sec, "dataHex", "messageHex")
		if data == nil {
			if s := findString(sec, "data", "message"); s != "" {
				data = []byte(s)
			}
		}
		sig := findBytes(sec, "signatureHex", "signature", "sigHex")
		if id == nil || data == nil || sig == nil {
			t.Skip("raw signature fields not found")
		}
		v, err := vaultysid.FromID(id, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(data, sig); err != nil {
			t.Fatalf("VAULTYS_RAW signature rejected: %v", err)
		}
		if v.VerifyHandshake(data, sig) == nil {
			t.Fatal("VAULTYS_RAW signature must not verify as handshake")
		}
	})
}

func section(root map[string]interface{}, names ...string) map[string]interface{} {
	for _, n := range names {
		for k, v := range root {
			if strings.EqualFold(k, n) {
				if m, ok := v.(map[string]interface{}); ok {
					return m
				}
			}
		}
	}
	return nil
}

func findString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if s, ok := findValue(m, key, 4).(string); ok {
			return s
		}
	}
	return ""
}

func findBytes(m map[string]interface{}, keys ...string) []byte {
	for _, key := range keys {
		s, ok := findValue(m, key, 4).(string)
		if !ok || s == "" {
			continue
		}
		if b, err := hex.DecodeString(s); err == nil {
			return b
		}
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			return b
		}
	}
	return nil
}

func findValue(v interface{}, key string, depth int) interface{} {
	if depth < 0 {
		return nil
	}
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if strings.EqualFold(k, key) {
				return val
			}
		}
		for _, val := range t {
			if r := findValue(val, key, depth-1); r != nil {
				return r
			}
		}
	case []interface{}:
		for _, val := range t {
			if r := findValue(val, key, depth-1); r != nil {
				return r
			}
		}
	}
	return nil
}

func findStep(m map[string]interface{}, name string) map[string]interface{} {
	steps, ok := findValue(m, "steps", 2).([]interface{})
	if !ok {
		return nil
	}
	for _, s := range steps {
		if sm, ok := s.(map[string]interface{}); ok {
			if n, _ := sm["name"].(string); strings.EqualFold(n, name) {
				return sm
			}
		}
	}
	return nil
}

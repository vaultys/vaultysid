package test

import (
	"encoding/hex"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// TestMsgpackCompatibility tests msgpack decoding compatibility with TypeScript
func TestMsgpackCompatibility(t *testing.T) {
	// This is the exact hex from TypeScript test vector for Ed25519 FIDO2Manager secret
	secretHex := "85a17601a166c4205bf35d0ee07a0bc90d2d759c91d9620977ab06d287c034b88a53a860e1e6d581a17411a163c42ca401010327200621d8405820df64044e19b516f8ee0fe7820c98c097e1c0ca33ac6a1fc1bcf234a544b000f0a165c420f7abd142e653c07732bf6383935999256f775a5a5f09c8d2c9b5b380be30025f"

	secretBytes, err := hex.DecodeString(secretHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	t.Logf("Secret bytes length: %d", len(secretBytes))
	t.Logf("First byte (msgpack type): 0x%02x", secretBytes[0])

	// Try to decode as a generic map
	var genericMap map[string]interface{}
	if err := msgpack.Unmarshal(secretBytes, &genericMap); err != nil {
		t.Fatalf("Failed to decode as generic map: %v", err)
	}

	t.Logf("Decoded map keys: %v", getMapKeys(genericMap))

	// Check each field
	for key, value := range genericMap {
		switch key {
		case "v":
			if v, ok := value.(int64); ok {
				t.Logf("Version (v): %d", v)
			} else {
				t.Logf("Version (v): %v (type %T)", value, value)
			}
		case "f":
			if v, ok := value.([]byte); ok {
				t.Logf("FID (f): %d bytes, hex: %x...", len(v), v[:8])
			} else {
				t.Logf("FID (f): %v (type %T)", value, value)
			}
		case "t":
			if v, ok := value.(int64); ok {
				t.Logf("Transports (t): %d", v)
			} else {
				t.Logf("Transports (t): %v (type %T)", value, value)
			}
		case "c":
			if v, ok := value.([]byte); ok {
				t.Logf("COSE key (c): %d bytes, hex: %x...", len(v), v[:8])
			} else {
				t.Logf("COSE key (c): %v (type %T)", value, value)
			}
		case "e":
			if v, ok := value.([]byte); ok {
				t.Logf("Cypher secret (e): %d bytes", len(v))
			} else {
				t.Logf("Cypher secret (e): %v (type %T)", value, value)
			}
		default:
			t.Logf("Unknown key '%s': %v (type %T)", key, value, value)
		}
	}

	// Now try to decode into our struct format
	type ExportFIDO2DataCompat struct {
		V interface{} `msgpack:"v"` // Version - can be int or omitted
		F []byte      `msgpack:"f"` // FID
		T interface{} `msgpack:"t"` // Transports - can be int or omitted
		C []byte      `msgpack:"c"` // COSE key (raw CBOR bytes)
		E []byte      `msgpack:"e"` // Cypher secret/public key
	}

	var data ExportFIDO2DataCompat
	if err := msgpack.Unmarshal(secretBytes, &data); err != nil {
		t.Fatalf("Failed to decode into struct: %v", err)
	}

	t.Logf("\nDecoded struct:")
	t.Logf("  Version: %v (type %T)", data.V, data.V)
	t.Logf("  FID: %d bytes", len(data.F))
	t.Logf("  Transports: %v (type %T)", data.T, data.T)
	t.Logf("  COSE key: %d bytes", len(data.C))
	t.Logf("  Cypher secret: %d bytes", len(data.E))

	// Extract actual values
	var version int
	switch v := data.V.(type) {
	case int:
		version = v
	case int8:
		version = int(v)
	case int16:
		version = int(v)
	case int32:
		version = int(v)
	case int64:
		version = int(v)
	case uint:
		version = int(v)
	case uint8:
		version = int(v)
	case uint16:
		version = int(v)
	case uint32:
		version = int(v)
	case uint64:
		version = int(v)
	default:
		t.Logf("Unexpected version type: %T", v)
	}

	var transports int
	switch v := data.T.(type) {
	case int:
		transports = v
	case int8:
		transports = int(v)
	case int16:
		transports = int(v)
	case int32:
		transports = int(v)
	case int64:
		transports = int(v)
	case uint:
		transports = int(v)
	case uint8:
		transports = int(v)
	case uint16:
		transports = int(v)
	case uint32:
		transports = int(v)
	case uint64:
		transports = int(v)
	default:
		t.Logf("Unexpected transports type: %T", v)
	}

	t.Logf("\nExtracted values:")
	t.Logf("  Version: %d", version)
	t.Logf("  Transports: %d (0x%02x)", transports, transports)

	// Verify we can parse the COSE key
	if len(data.C) > 0 {
		t.Logf("\nCOSE key analysis:")
		t.Logf("  First bytes: %x", data.C[:10])
		t.Logf("  CBOR type indicator: 0x%02x", data.C[0])
		if data.C[0] == 0xa4 {
			t.Logf("  -> 0xa4 = CBOR map with 4 elements")
		} else if data.C[0] == 0xa3 {
			t.Logf("  -> 0xa3 = CBOR map with 3 elements")
		} else if data.C[0] == 0xa5 {
			t.Logf("  -> 0xa5 = CBOR map with 5 elements")
		}
	}
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

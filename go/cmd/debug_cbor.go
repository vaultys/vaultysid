package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	// COSE key from TypeScript test vector
	coseHex := "a401010327200621d8405820df64044e19b516f8ee0fe7820c98c097e1c0ca33ac6a1fc1bcf234a544b000f0"

	coseBytes, err := hex.DecodeString(coseHex)
	if err != nil {
		log.Fatalf("Failed to decode hex: %v", err)
	}

	fmt.Printf("COSE key bytes (%d bytes): %x\n", len(coseBytes), coseBytes)
	fmt.Println()

	// Try to decode as generic map
	var genericMap map[interface{}]interface{}
	if err := cbor.Unmarshal(coseBytes, &genericMap); err != nil {
		log.Printf("Failed to decode as generic map: %v", err)
	} else {
		fmt.Println("Decoded as generic map:")
		for k, v := range genericMap {
			fmt.Printf("  Key %v (type %T): Value %v (type %T)\n", k, k, v, v)
			if bytes, ok := v.([]byte); ok {
				fmt.Printf("    Hex: %x\n", bytes)
			}
		}
	}
	fmt.Println()

	// Try to decode as map[int]interface{}
	var intMap map[int]interface{}
	if err := cbor.Unmarshal(coseBytes, &intMap); err != nil {
		log.Printf("Failed to decode as int map: %v", err)
	} else {
		fmt.Println("Decoded as int map:")
		for k, v := range intMap {
			fmt.Printf("  Key %d: Value %v (type %T)\n", k, v, v)
			if bytes, ok := v.([]byte); ok {
				fmt.Printf("    Hex: %x\n", bytes)
			}
		}
	}
	fmt.Println()

	// Test msgpack decoding of the full secret
	secretHex := "85a17601a166c4205bf35d0ee07a0bc90d2d759c91d9620977ab06d287c034b88a53a860e1e6d581a17411a163c42ca401010327200621d8405820df64044e19b516f8ee0fe7820c98c097e1c0ca33ac6a1fc1bcf234a544b000f0a165c420f7abd142e653c07732bf6383935999256f775a5a5f09c8d2c9b5b380be30025f"

	secretBytes, err := hex.DecodeString(secretHex)
	if err != nil {
		log.Fatalf("Failed to decode secret hex: %v", err)
	}

	fmt.Printf("Secret bytes (%d bytes), first 20: %x\n", len(secretBytes), secretBytes[:20])
	fmt.Printf("MessagePack format indicator: 0x%02x\n", secretBytes[0])
	fmt.Println("0x85 = fixmap with 5 elements")
	fmt.Println()

	// Analyze the P-256 COSE key
	p256CoseHex := "a501020326200621d84058204b6cdfa33479015f9f0a1ef4c2e48e58e4aa6e3e9d4946bd6139e12a9a18b84e22d84058203be93b58c8cb0ba361b45118f60e00f54df5e816a67fffe88eb9cb9abeb1d012"

	p256Bytes, err := hex.DecodeString(p256CoseHex)
	if err != nil {
		log.Fatalf("Failed to decode P-256 hex: %v", err)
	}

	fmt.Printf("P-256 COSE key bytes (%d bytes)\n", len(p256Bytes))

	var p256Map map[int]interface{}
	if err := cbor.Unmarshal(p256Bytes, &p256Map); err != nil {
		log.Printf("Failed to decode P-256 as int map: %v", err)
	} else {
		fmt.Println("P-256 decoded as int map:")
		for k, v := range p256Map {
			fmt.Printf("  Key %d: Value %v (type %T)\n", k, v, v)
			if bytes, ok := v.([]byte); ok {
				fmt.Printf("    Hex: %x\n", bytes)
			}
		}
	}
}

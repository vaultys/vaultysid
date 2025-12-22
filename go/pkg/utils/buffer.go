package utils

import (
	"encoding/base64"
	"encoding/hex"
)

// ToBase64 converts bytes to base64 string
func ToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// ToHex converts bytes to hex string
func ToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// ToUTF8 converts bytes to UTF-8 string
func ToUTF8(data []byte) string {
	return string(data)
}

// FromBase64 converts base64 string to bytes
func FromBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// FromHex converts hex string to bytes
func FromHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// FromUTF8 converts UTF-8 string to bytes
func FromUTF8(s string) []byte {
	return []byte(s)
}

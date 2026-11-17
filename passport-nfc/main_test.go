package main

import (
	"strings"
	"testing"
)

func TestNFCRequestAndReaderSelection(t *testing.T) {
	valid := `{"operation":"sign","mrz":"test","challenges":["AAAAAAAAAAA=","AQAAAAAAAAA=","AgAAAAAAAAA=","AwAAAAAAAAA="],"responseLength":64}`
	if _, err := readRequest(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		strings.Replace(valid, "AQAAAAAAAAA=", "AAAAAAAAAAA=", 1),
		strings.Replace(valid, "AQAAAAAAAAA=", "AQAAAA==", 1),
		strings.Replace(valid, ":64", ":513", 1),
		valid + `{}`,
	} {
		if _, err := readRequest(strings.NewReader(input)); err == nil {
			t.Fatal("accepted invalid request")
		}
	}
	if _, err := selectReader(nil, ""); err == nil {
		t.Fatal("selected a reader without hardware")
	}
	if _, err := selectReader([]string{"one", "two"}, ""); err == nil {
		t.Fatal("selected an ambiguous reader")
	}
	if name, err := selectReader([]string{"one", "two"}, "two"); err != nil || name != "two" {
		t.Fatalf("reader selection failed: %s, %v", name, err)
	}
}

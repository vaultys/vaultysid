package chip

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
)

type fakeTransport func([]byte) []byte

func (transport fakeTransport) Transceive(_, _, _, _ int, _ []byte, _ int, command []byte) []byte {
	return transport(command)
}

func TestPassportApplicationAndBACFallback(t *testing.T) {
	t.Parallel()
	replies := [][]byte{{0x6a, 0x82}, {0x6a, 0x82}, {0x6a, 0x82}, {0x90, 0x00}, {0x69, 0x82}}
	var commands [][]byte
	session := iso7816.NewNfcSession(fakeTransport(func(command []byte) []byte {
		commands = append(commands, bytes.Clone(command))
		return replies[len(commands)-1]
	}))
	pass, err := password.NewPasswordMrzi("L898902C3", "740812", "120415")
	if err != nil {
		t.Fatal(err)
	}
	if err := openPassport(session, pass); err == nil || !strings.Contains(err.Error(), "BAC access failed") {
		t.Fatalf("unexpected access result: %v", err)
	}
	want := [][]byte{
		{0, 0xa4},
		{0, 0xa4},
		{0, 0xa4, 0x02, 0x0c, 0x02, 0x01, 0x1c},
		{0, 0xa4, 0x04, 0x0c, 0x07, 0xa0, 0, 0, 0x02, 0x47, 0x10, 0x01},
		{0, 0x84, 0, 0, 8},
	}
	if len(want) != len(commands) {
		t.Fatalf("unexpected command count: %d", len(commands))
	}
	for i, prefix := range want {
		if !bytes.HasPrefix(commands[i], prefix) {
			t.Fatalf("command %d: got %x, want prefix %x", i, commands[i], prefix)
		}
	}
}

type mockPassportSession struct {
	read   []uint16
	signed [][]byte
	maxLe  int
	failAt int
}

func (session *mockPassportSession) ReadFile(file uint16) ([]byte, error) {
	session.read = append(session.read, file)
	if file == dg15File {
		return []byte{0x6f, 0x02, 0x30, 0x00}, nil
	}
	return nil, nil
}

func (session *mockPassportSession) InternalAuthenticate(challenge []byte) ([]byte, error) {
	session.signed = append(session.signed, challenge)
	if len(session.signed) == session.failAt {
		return nil, errors.New("card removed")
	}
	return make([]byte, 256), nil
}

func (session *mockPassportSession) SetMaxLe(le int) { session.maxLe = le }

func TestAAOperations(t *testing.T) {
	t.Parallel()
	session := new(mockPassportSession)
	read, err := readDataGroups(session)
	if err != nil || len(read.DG15) == 0 || read.DG14 != nil {
		t.Fatalf("read result: %+v, %v", read, err)
	}
	if len(session.read) != 2 || session.read[0] != dg15File || session.read[1] != dg14File {
		t.Fatalf("read unexpected data groups: %v", session.read)
	}
	challenges := [][]byte{[]byte("12345678"), []byte("22345678"), []byte("32345678"), []byte("42345678")}
	const responseLength = 256
	signed, err := signChallenges(session, challenges, responseLength)
	if err != nil || len(signed) != 4 || session.maxLe != 65536 {
		t.Fatalf("sign result: %d responses, Le %d, %v", len(signed), session.maxLe, err)
	}
	for i, challenge := range challenges {
		if !bytes.Equal(session.signed[i], challenge) {
			t.Fatal("sign changed challenge order")
		}
	}
	session.signed = nil
	session.failAt = 2
	signed, err = signChallenges(session, challenges, responseLength)
	if err == nil || len(signed) != 0 || len(session.signed) != 2 {
		t.Fatal("returned a partial proof or continued after reader failure")
	}
}

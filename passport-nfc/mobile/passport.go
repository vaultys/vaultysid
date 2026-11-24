// Package passportaa exposes passport operations to native NFC transports.
package passportaa

import (
	"errors"
	"io"
	"log/slog"

	"github.com/vaultys/vaultysid/passport-nfc/internal/chip"
)

// Transceiver exchanges a raw ISO 7816 command with the connected passport.
// The response includes the trailing two status bytes.
type Transceiver interface {
	Exchange(command []byte) ([]byte, error)
}

type DataGroups struct {
	dg15 []byte
	dg14 []byte
}

func (groups *DataGroups) DG15() []byte { return groups.dg15 }
func (groups *DataGroups) DG14() []byte { return groups.dg14 }

func init() {
	// This bound Go runtime is dedicated to the passport reader.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func open(mrz string, link Transceiver) (*chip.Session, error) {
	if link == nil {
		return nil, errors.New("an NFC transceiver is required")
	}
	pass, err := chip.Password(mrz)
	if err != nil {
		return nil, err
	}
	return chip.Open(pass, link.Exchange)
}

func protect(err *error) {
	if recover() != nil {
		*err = errors.New("could not process the passport chip response")
	}
}

func ReadPassport(mrz string, link Transceiver) (groups *DataGroups, err error) {
	defer protect(&err)
	session, err := open(mrz, link)
	if err != nil {
		return nil, err
	}
	result, err := session.Read()
	if err != nil {
		return nil, err
	}
	return &DataGroups{dg15: result.DG15, dg14: result.DG14}, nil
}

// SignPassport takes four consecutive eight-byte challenges. It returns the
// four chip responses concatenated in the same order.
func SignPassport(mrz string, link Transceiver, packed []byte, responseLength int) (signatures []byte, err error) {
	defer protect(&err)
	if len(packed) != 32 {
		return nil, errors.New("passport AA requires four eight-byte challenges")
	}
	challenges := [][]byte{packed[:8], packed[8:16], packed[16:24], packed[24:]}
	if err := chip.ValidateChallenges(challenges, responseLength); err != nil {
		return nil, err
	}
	session, err := open(mrz, link)
	if err != nil {
		return nil, err
	}
	responses, err := session.Sign(challenges, responseLength)
	if err != nil {
		return nil, err
	}
	for _, response := range responses {
		signatures = append(signatures, response...)
	}
	return signatures, nil
}

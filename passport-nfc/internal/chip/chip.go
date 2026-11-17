package chip

import (
	"errors"
	"github.com/gmrtd/gmrtd/bac"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/pace"
	"github.com/gmrtd/gmrtd/password"
)

const (
	cardAccessFile = 0x011c
	dg14File       = 0x010e
	dg15File       = 0x010f
)

func openPassport(session *iso7816.NfcSession, pass *password.Password) error {
	doc := new(document.Document)
	// Some chips reject explicit selection of the master file.
	_ = session.SelectMF()
	data, err := session.ReadFile(cardAccessFile)
	if err != nil {
		return errors.New("could not read the passport's access parameters")
	}
	doc.Mf.CardAccess, err = document.NewCardAccess(data)
	if err != nil {
		return errors.New("invalid passport access parameters")
	}
	_, _, err = pace.NewPace(session, doc, pass).DoPACE()
	// An unsupported local algorithm means PACE did not send an authentication command.
	if err != nil && !errors.Is(err, pace.ErrPACEUnsupportedLocally) {
		return errors.New("passport PACE access failed; check the MRZ and keep the passport on the reader")
	}
	selected, err := session.SelectAid([]byte{0xa0, 0, 0, 0x02, 0x47, 0x10, 0x01})
	if err != nil || !selected {
		return errors.New("could not select the ePassport application")
	}
	if session.SM() == nil {
		if _, err := bac.NewBAC(session, doc, pass).DoBAC(); err != nil || session.SM() == nil {
			return errors.New("passport BAC access failed; check the MRZ and keep the passport on the reader")
		}
	}
	return nil
}

func ValidateChallenges(challenges [][]byte, responseLength int) error {
	if len(challenges) != 4 || responseLength < 64 || responseLength > 512 {
		return errors.New("passport AA requires four challenges and a supported response length")
	}
	seen := make(map[[8]byte]bool, 4)
	for _, challenge := range challenges {
		if len(challenge) != 8 || seen[[8]byte(challenge)] {
			return errors.New("passport AA requires four distinct eight-byte challenges")
		}
		seen[[8]byte(challenge)] = true
	}
	return nil
}

type transport struct {
	exchange func([]byte) ([]byte, error)
	failed   bool
}

func (t *transport) Transceive(_, _, _, _ int, _ []byte, _ int, command []byte) []byte {
	if t.failed {
		return nil
	}
	reply, err := t.exchange(command)
	if err != nil || len(reply) < 2 || len(reply) > 65538 {
		t.failed = true
		return nil
	}
	return reply
}

type Session struct {
	nfc       *iso7816.NfcSession
	transport *transport
}

func Password(mrz string) (*password.Password, error) {
	if len(mrz) == 0 || len(mrz) > 256 {
		return nil, errors.New("invalid passport MRZ; check the machine-readable lines")
	}
	pass, err := password.NewPasswordMrz(mrz)
	if err != nil {
		return nil, errors.New("invalid passport MRZ; check the machine-readable lines")
	}
	return pass, nil
}

func Open(pass *password.Password, exchange func([]byte) ([]byte, error)) (*Session, error) {
	transport := &transport{exchange: exchange}
	nfc := iso7816.NewNfcSession(transport)
	err := openPassport(nfc, pass)
	if transport.failed {
		return nil, errors.New("communication with the passport was interrupted")
	}
	if err != nil {
		return nil, err
	}
	return &Session{nfc: nfc, transport: transport}, nil
}

type DataGroups struct {
	DG15 []byte
	DG14 []byte
}

func (session *Session) Read() (DataGroups, error) {
	groups, err := readDataGroups(session.nfc)
	if session.transport.failed {
		return DataGroups{}, errors.New("communication with the passport was interrupted")
	}
	return groups, err
}

type passportSession interface {
	ReadFile(uint16) ([]byte, error)
	InternalAuthenticate([]byte) ([]byte, error)
	SetMaxLe(int)
}

func readDataGroups(session passportSession) (DataGroups, error) {
	dg15, err := session.ReadFile(dg15File)
	if err != nil {
		return DataGroups{}, errors.New("could not read passport DG15")
	}
	if len(dg15) == 0 {
		return DataGroups{}, errors.New("passport has no DG15 Active Authentication key")
	}
	dg14, err := session.ReadFile(dg14File)
	if err != nil {
		return DataGroups{}, errors.New("could not read passport DG14")
	}
	return DataGroups{DG15: dg15, DG14: dg14}, nil
}

func (session *Session) Sign(challenges [][]byte, responseLength int) ([][]byte, error) {
	signatures, err := signChallenges(session.nfc, challenges, responseLength)
	if session.transport.failed {
		return nil, errors.New("communication with the passport was interrupted")
	}
	return signatures, err
}

func signChallenges(session passportSession, challenges [][]byte, responseLength int) ([][]byte, error) {
	if err := ValidateChallenges(challenges, responseLength); err != nil {
		return nil, err
	}
	// Secure messaging can push a 256-byte RSA signature beyond a short APDU.
	// gmrtd handles a chip that rejects an extended expected length.
	if responseLength > 224 {
		session.SetMaxLe(65536)
	}
	signatures := make([][]byte, 0, len(challenges))
	for _, challenge := range challenges {
		signature, err := session.InternalAuthenticate(challenge)
		if err != nil {
			return nil, errors.New("the passport rejected Active Authentication or was removed")
		}
		if len(signature) != responseLength {
			return nil, errors.New("unexpected passport signature length")
		}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

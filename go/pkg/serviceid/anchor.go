package serviceid

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// AnchorLabel is the domain-separation label of a service anchor signature (RFC §8).
const AnchorLabel = "vaultysid/service-anchor/v1"

// AnchorPath is where a service serves its anchor, under its origin.
const AnchorPath = "/.well-known/vaultysid-service"

var anchorHeader = []byte{0x01, 0x01}

const (
	maxAnchorServiceID = 300
	maxAnchorID        = 8192
)

func lpBytes(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// publicV1 returns the version-1 serialized public id of an identity.
func publicV1(identity *vaultysid.VaultysID) (*vaultysid.VaultysID, error) {
	copyID, err := vaultysid.FromID(identity.ToBytes(), nil)
	if err != nil {
		return nil, err
	}
	if err := copyID.ToVersion(1); err != nil {
		return nil, err
	}
	return copyID, nil
}

// AnchorSignedData returns the bytes a service signs for its anchor.
func AnchorSignedData(serviceID string, id []byte) []byte {
	var b []byte
	b = append(b, lp(AnchorLabel)...)
	b = append(b, anchorHeader...)
	b = append(b, lp(serviceID)...)
	b = append(b, lpBytes(id)...)
	return b
}

// AnchorURL returns where the anchor of a web origin is served.
func AnchorURL(serviceID string) (string, error) {
	canonical, err := CanonicalServiceID(serviceID, false)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(canonical, "app:") {
		return "", errors.New("an app: service id has no web origin to publish an anchor")
	}
	return canonical + AnchorPath, nil
}

// CreateAnchor returns the anchor of identity for the canonical serviceID.
func CreateAnchor(identity *vaultysid.VaultysID, serviceID string) ([]byte, error) {
	if !IsCanonicalServiceID(serviceID, false) {
		return nil, ErrInvalidServiceID
	}
	public, err := publicV1(identity)
	if err != nil {
		return nil, err
	}
	id := public.ToBytes()
	sig, err := identity.Sign(AnchorSignedData(serviceID, id))
	if err != nil {
		return nil, err
	}
	if len(sig) == 0 || len(sig) > 0xffff {
		return nil, errors.New("the identity cannot sign the anchor")
	}
	var out []byte
	out = append(out, anchorHeader...)
	out = append(out, lp(serviceID)...)
	out = append(out, lpBytes(id)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(sig)))
	out = append(out, sig...)
	return out, nil
}

func readLp(b []byte, offset, max int) ([]byte, int, bool) {
	if offset+4 > len(b) {
		return nil, 0, false
	}
	n := int(binary.BigEndian.Uint32(b[offset:]))
	if n == 0 || n > max || offset+4+n > len(b) {
		return nil, 0, false
	}
	return b[offset+4 : offset+4+n], offset + 4 + n, true
}

// VerifyAnchor verifies an anchor fetched from the canonical origin serviceID and
// returns the service's public identity, or nil on any defect. It never panics.
func VerifyAnchor(anchor []byte, serviceID string) (identity *vaultysid.VaultysID) {
	defer func() {
		if recover() != nil {
			identity = nil
		}
	}()
	if len(anchor) < len(anchorHeader) || !bytes.Equal(anchor[:2], anchorHeader) {
		return nil
	}
	origin, next, ok := readLp(anchor, 2, maxAnchorServiceID)
	if !ok {
		return nil
	}
	id, next, ok := readLp(anchor, next, maxAnchorID)
	if !ok || next+2 > len(anchor) {
		return nil
	}
	sigLen := int(binary.BigEndian.Uint16(anchor[next:]))
	sigStart := next + 2
	if sigLen == 0 || sigStart+sigLen != len(anchor) {
		return nil
	}
	if !utf8.Valid(origin) || string(origin) != serviceID || !IsCanonicalServiceID(serviceID, false) {
		return nil
	}
	parsed, err := vaultysid.FromID(id, nil)
	if err != nil {
		return nil
	}
	public, err := publicV1(parsed)
	if err != nil || !bytes.Equal(public.ToBytes(), id) {
		return nil
	}
	if public.Verify(AnchorSignedData(serviceID, id), anchor[sigStart:]) != nil {
		return nil
	}
	return public
}

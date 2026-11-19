// Package serviceid implements service identities and service anchors
// (rfc/SERVICE-IDENTITIES.md): one unlinkable VaultysID per service, derived
// from a master secret, and the signed identity a service publishes under its
// web origin.
package serviceid

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"

	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// Salt is the HKDF salt of a service identity (RFC §4).
const Salt = "vaultysid/service-identity/v1"

// MasterSecretLength is the length of the master secret, in bytes.
const MasterSecretLength = 32

// EntropyLength is the length of the entropy handed to FromEntropyAlg.
const EntropyLength = 32

// MaxServiceIDInputLength is the longest accepted service id input.
const MaxServiceIDInputLength = 300

const derivationVersion = "v1"
const typePQFlag = 0x10

// ErrInvalidServiceID is returned for any service id the grammar refuses.
var ErrInvalidServiceID = errors.New("invalid service id")

// ErrInvalidMasterSecret is returned for a master secret that is not 32 bytes or is all zero.
var ErrInvalidMasterSecret = errors.New("invalid master secret")

// Options selects the identity derived for a service.
type Options struct {
	// Alg is "ed25519" (default), "dilithium" or "dilithium_ed25519".
	Alg string
	// Role is "machine", "person" (default) or "organization".
	Role string
	// PostQuantum derives the post-quantum type 0x10 | role (rfc/PQ-ENCRYPTION.md).
	PostQuantum bool
	// AllowDevelopmentHosts accepts http, localhost, *.localhost and IP literals (RFC §3.2).
	AllowDevelopmentHosts bool
}

var roles = map[string]vaultysid.IdentityType{"machine": vaultysid.TypeMachine, "person": vaultysid.TypePerson, "organization": vaultysid.TypeOrganization}

var (
	printableASCII = regexp.MustCompile(`^[\x21-\x7e]+$`)
	forbidden      = regexp.MustCompile(`[%\\@?#]`)
	webRe          = regexp.MustCompile(`(?i)^(https?)://([^/:\[\]]*)(?::([^/]*))?(/?)$`)
	webIPv6Re      = regexp.MustCompile(`(?i)^(https?)://(\[[0-9a-f:.]+\])(?::([^/]*))?(/?)$`)
	appRe          = regexp.MustCompile(`^app:(.*)$`)
	labelRe        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	ipv4Re         = regexp.MustCompile(`^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}$`)
	portRe         = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	numericRe      = regexp.MustCompile(`^[0-9]+$`)
	hexNumberRe    = regexp.MustCompile(`^0x[0-9a-f]*$`)
	defaultPorts   = map[string]string{"http": "80", "https": "443"}
)

func isDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !labelRe.MatchString(label) {
			return false
		}
		if len(label) >= 4 && label[2:4] == "--" && !strings.HasPrefix(label, "xn--") {
			return false
		}
	}
	return true
}

func endsInNumber(host string) bool {
	last := host[strings.LastIndex(host, ".")+1:]
	return numericRe.MatchString(last) || hexNumberRe.MatchString(last)
}

func canonicalPort(scheme, port string, present bool) (string, error) {
	if !present {
		return "", nil
	}
	if !portRe.MatchString(port) {
		return "", ErrInvalidServiceID
	}
	if n, _ := strconv.Atoi(port); n > 65535 {
		return "", ErrInvalidServiceID
	}
	if port == defaultPorts[scheme] {
		return "", nil
	}
	return ":" + port, nil
}

// punycodeLabelValid refuses `xn--` labels that cannot be decoded (the TypeScript
// reference refuses them through the WHATWG parser). It only decodes to check
// validity; the output never contains the decoded form.
func punycodeLabelValid(label string) bool {
	if !strings.HasPrefix(label, "xn--") {
		return true
	}
	_, ok := decodePunycode(label[4:])
	return ok
}

// CanonicalServiceID returns the canonical identifier of a service (RFC §3), or ErrInvalidServiceID.
func CanonicalServiceID(input string, allowDevelopmentHosts bool) (string, error) {
	if len(input) == 0 || len(input) > MaxServiceIDInputLength || !printableASCII.MatchString(input) || forbidden.MatchString(input) {
		return "", ErrInvalidServiceID
	}
	if m := appRe.FindStringSubmatch(input); m != nil {
		if !isDNSName(m[1]) {
			return "", ErrInvalidServiceID
		}
		return input, nil
	}
	if m := webIPv6Re.FindStringSubmatch(input); m != nil {
		return canonicalIPv6Origin(m, allowDevelopmentHosts)
	}
	m := webRe.FindStringSubmatchIndex(input)
	if m == nil {
		return "", ErrInvalidServiceID
	}
	scheme := strings.ToLower(input[m[2]:m[3]])
	host := strings.ToLower(input[m[4]:m[5]])
	portPresent := m[6] >= 0
	port := ""
	if portPresent {
		port = input[m[6]:m[7]]
	}
	var developmentHost bool
	switch {
	case ipv4Re.MatchString(host), host == "localhost":
		developmentHost = true
	case isDNSName(host) && !endsInNumber(host):
		developmentHost = strings.HasSuffix(host, ".localhost")
		for _, label := range strings.Split(host, ".") {
			if !punycodeLabelValid(label) {
				return "", ErrInvalidServiceID
			}
		}
	default:
		return "", ErrInvalidServiceID
	}
	if (developmentHost || scheme == "http") && !allowDevelopmentHosts {
		return "", ErrInvalidServiceID
	}
	portPart, err := canonicalPort(scheme, port, portPresent)
	if err != nil {
		return "", err
	}
	return scheme + "://" + host + portPart, nil
}

// canonicalIPv6Origin accepts an IPv6 literal (development only) in the exact
// form the WHATWG parser serializes: RFC 5952 text, lowercase, without an
// embedded IPv4 part (which WHATWG rewrites in hexadecimal). Anything else is
// refused, never normalized.
func canonicalIPv6Origin(m []string, allowDevelopmentHosts bool) (string, error) {
	if !allowDevelopmentHosts {
		return "", ErrInvalidServiceID
	}
	scheme := strings.ToLower(m[1])
	host := strings.ToLower(m[2])
	inner := host[1 : len(host)-1]
	if strings.Contains(inner, ".") {
		return "", ErrInvalidServiceID
	}
	addr, err := netip.ParseAddr(inner)
	if err != nil || !addr.Is6() || addr.Zone() != "" || "["+addr.String()+"]" != host {
		return "", ErrInvalidServiceID
	}
	portPart, err := canonicalPort(scheme, m[3], m[3] != "" || strings.Contains(m[0][len(m[1])+3+len(m[2]):], ":"))
	if err != nil {
		return "", err
	}
	return scheme + "://" + host + portPart, nil
}

// IsCanonicalServiceID reports whether serviceID is already canonical.
func IsCanonicalServiceID(serviceID string, allowDevelopmentHosts bool) bool {
	c, err := CanonicalServiceID(serviceID, allowDevelopmentHosts)
	return err == nil && c == serviceID
}

func lp(s string) []byte {
	out := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(out, uint32(len(s)))
	copy(out[4:], s)
	return out
}

func resolve(opts Options) (alg, role string, idType vaultysid.IdentityType, err error) {
	alg, role = opts.Alg, opts.Role
	if alg == "" {
		alg = "ed25519"
	}
	if role == "" {
		role = "person"
	}
	if alg != "ed25519" && alg != "dilithium" && alg != "dilithium_ed25519" {
		return "", "", 0, fmt.Errorf("unsupported algorithm %q", alg)
	}
	t, ok := roles[role]
	if !ok {
		return "", "", 0, fmt.Errorf("unsupported role %q", role)
	}
	if opts.PostQuantum && alg == "ed25519" {
		return "", "", 0, errors.New("post-quantum identities require a dilithium or dilithium_ed25519 key manager")
	}
	if opts.PostQuantum {
		t |= typePQFlag
	}
	return alg, role, t, nil
}

// Info returns the HKDF info of a service identity: lp("v1") || lp(alg) || lp(type name) || lp(canonical).
func Info(alg, role string, postQuantum bool, canonical string) []byte {
	typeName := role
	if postQuantum {
		typeName += "-pq"
	}
	var b []byte
	b = append(b, lp(derivationVersion)...)
	b = append(b, lp(alg)...)
	b = append(b, lp(typeName)...)
	b = append(b, lp(canonical)...)
	return b
}

func checkMaster(master []byte) error {
	if len(master) != MasterSecretLength {
		return ErrInvalidMasterSecret
	}
	for _, b := range master {
		if b != 0 {
			return nil
		}
	}
	return ErrInvalidMasterSecret
}

// DeriveEntropy returns the secret entropy of a service identity (RFC §4). The caller must erase it.
func DeriveEntropy(master []byte, serviceID string, opts Options) ([]byte, error) {
	if err := checkMaster(master); err != nil {
		return nil, err
	}
	alg, role, _, err := resolve(opts)
	if err != nil {
		return nil, err
	}
	canonical, err := CanonicalServiceID(serviceID, opts.AllowDevelopmentHosts)
	if err != nil {
		return nil, err
	}
	r := hkdf.New(sha256.New, master, []byte(Salt), Info(alg, role, opts.PostQuantum, canonical))
	out := make([]byte, EntropyLength)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Derive returns the VaultysID of serviceID derived from master (RFC §4).
// Deterministic; two services give identities with no common value.
func Derive(master []byte, serviceID string, opts Options) (*vaultysid.VaultysID, error) {
	alg, _, idType, err := resolve(opts)
	if err != nil {
		return nil, err
	}
	if opts.PostQuantum {
		return nil, errors.New("post-quantum identity types are not implemented in Go on this branch")
	}
	entropy, err := DeriveEntropy(master, serviceID, opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range entropy {
			entropy[i] = 0
		}
	}()
	return vaultysid.FromEntropyAlg(append([]byte(nil), entropy...), idType, alg)
}

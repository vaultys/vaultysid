package xwingchannel

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/serviceid"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// Handshake metadata keys (rfc/SECURE-CHANNEL.md §4).
const (
	BindingMetadataKey = "vaultys.channel-binding"
	ServiceMetadataKey = "vaultys.service"
	protocol           = "p2p"
	service            = "auth"
)

// HandshakeOptions of the bound handshake.
type HandshakeOptions struct {
	// ExpectedPeer, initiator only: the identity the responder must have (for
	// example from a service anchor). Checked before signing COMPLETE.
	ExpectedPeer *vaultysid.VaultysID
	// Timeout for each message (default 30 s).
	Timeout time.Duration
	// AllowDevelopmentHosts, as for serviceid.CanonicalServiceID.
	AllowDevelopmentHosts bool
}

// Result of a bound handshake. The caller stores Contact and Certificate (for
// example with idmanager.Manager.SaveContact); nothing is stored here.
type Result struct {
	Contact     *vaultysid.VaultysID
	Certificate []byte
	Session     *Session
}

// Fingerprint is SHA-256 of the version-1 serialized public id of an identity.
func Fingerprint(identity *vaultysid.VaultysID) ([]byte, error) {
	c, err := vaultysid.FromID(identity.ToBytes(), nil)
	if err != nil {
		return nil, fail(CodeInvalidKey)
	}
	if err := c.ToVersion(1); err != nil {
		return nil, fail(CodeInvalidKey)
	}
	sum := sha256.Sum256(c.ToBytes())
	return sum[:], nil
}

func checkArguments(serviceID string, metadata map[string]string, allowDev bool) error {
	if !serviceid.IsCanonicalServiceID(serviceID, allowDev) {
		return fail(CodeInvalidServiceID)
	}
	for k := range metadata {
		if k == BindingMetadataKey || k == ServiceMetadataKey {
			return fail(CodeInvalidArgument)
		}
	}
	return nil
}

func abort(s *Session, code string) error {
	_ = s.Send([]byte{0})
	_ = s.Close()
	return fail(code)
}

func receiveOrAbort(s *Session, timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		d, err := s.Receive()
		ch <- result{d, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			var e *Error
			if ok := asError(r.err, &e); ok {
				return nil, r.err
			}
			return nil, fail(CodeHandshakeFailed)
		}
		return r.data, nil
	case <-timer.C:
		_ = s.Close()
		return nil, fail(CodeTimeout)
	}
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

// ConnectOverXWing establishes an X-Wing channel over t as initiator, then runs
// the VaultysID handshake inside it, bound to the channel and to serviceID.
// serviceID must be canonical; both sides must pass the same string.
func ConnectOverXWing(self *vaultysid.VaultysID, t Transport, serviceID string, metadata map[string]string, opts HandshakeOptions) (*Result, error) {
	if err := checkArguments(serviceID, metadata, opts.AllowDevelopmentHosts); err != nil {
		return nil, err
	}
	timeout, err := timeoutOf(opts.Timeout)
	if err != nil {
		return nil, err
	}
	var expected []byte
	if opts.ExpectedPeer != nil {
		if expected, err = Fingerprint(opts.ExpectedPeer); err != nil {
			return nil, fail(CodeInvalidArgument)
		}
	}
	s, err := Initiate(t, Options{Timeout: timeout})
	if err != nil {
		return nil, err
	}
	binding := base64.StdEncoding.EncodeToString(s.Binding)
	c := challenger.New(self)
	for k, v := range metadata {
		c.SetMetadata(k, v)
	}
	c.SetMetadata(BindingMetadataKey, binding)
	c.SetMetadata(ServiceMetadataKey, serviceID)
	init, err := c.Init(protocol, service)
	if err != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}
	raw, err := challenger.Serialize(init)
	if err != nil || s.Send(raw) != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}

	step1Raw, err := receiveOrAbort(s, timeout)
	if err != nil {
		return nil, err
	}
	step1, err := challenger.Deserialize(step1Raw)
	if err != nil || step1.State != challenger.StateStep1 {
		return nil, abort(s, CodeHandshakeFailed)
	}
	// checked BEFORE signing: the responder signed OUR transcript and the SAME service
	if v, ok := step1.Metadata.PK2.Get(BindingMetadataKey); !ok || v != binding {
		return nil, abort(s, CodeBindingMismatch)
	}
	if v, ok := step1.Metadata.PK2.Get(ServiceMetadataKey); !ok || v != serviceID {
		return nil, abort(s, CodeServiceMismatch)
	}
	if expected != nil {
		peer, err := vaultysid.FromID(step1.PK2, nil)
		if err != nil {
			return nil, abort(s, CodeHandshakeFailed)
		}
		fp, err := Fingerprint(peer)
		if err != nil || !bytes.Equal(fp, expected) {
			return nil, abort(s, CodePeerMismatch)
		}
	}
	// Step2 verifies sign2 (so the identity checked above is the one that signed) and signs COMPLETE.
	complete, err := c.Step2(step1)
	if err != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}
	completeRaw, err := challenger.Serialize(complete)
	if err != nil || s.Send(completeRaw) != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}
	contact, err := c.GetRemoteVaultysID()
	if err != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}
	cert, _ := c.GetCertificate()
	return &Result{Contact: contact, Certificate: cert, Session: s}, nil
}

// AcceptOverXWing accepts an X-Wing channel over t, then the VaultysID handshake
// inside it, bound to the channel and to serviceID.
func AcceptOverXWing(self *vaultysid.VaultysID, t Transport, serviceID string, metadata map[string]string, opts HandshakeOptions) (*Result, error) {
	if err := checkArguments(serviceID, metadata, opts.AllowDevelopmentHosts); err != nil {
		return nil, err
	}
	timeout, err := timeoutOf(opts.Timeout)
	if err != nil {
		return nil, err
	}
	s, err := Accept(t, Options{Timeout: timeout})
	if err != nil {
		return nil, err
	}
	binding := base64.StdEncoding.EncodeToString(s.Binding)

	initRaw, err := receiveOrAbort(s, timeout)
	if err != nil {
		return nil, err
	}
	init, err := challenger.Deserialize(initRaw)
	if err != nil || init.State != challenger.StateInit || init.Protocol != protocol || init.Service != service {
		return nil, abort(s, CodeHandshakeFailed)
	}
	// checked BEFORE signing STEP1
	if v, ok := init.Metadata.PK1.Get(BindingMetadataKey); !ok || v != binding {
		return nil, abort(s, CodeBindingMismatch)
	}
	if v, ok := init.Metadata.PK1.Get(ServiceMetadataKey); !ok || v != serviceID {
		return nil, abort(s, CodeServiceMismatch)
	}
	c := challenger.New(self)
	for k, v := range metadata {
		c.SetMetadata(k, v)
	}
	c.SetMetadata(BindingMetadataKey, binding)
	c.SetMetadata(ServiceMetadataKey, serviceID)
	step1, err := c.Step1(init)
	if err != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}
	step1Raw, err := challenger.Serialize(step1)
	if err != nil || s.Send(step1Raw) != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}

	completeRaw, err := receiveOrAbort(s, timeout)
	if err != nil {
		return nil, err
	}
	complete, err := challenger.Deserialize(completeRaw)
	if err != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}
	// Finalize checks sign1 and that everything we signed (both bindings included) is unchanged.
	if err := c.Finalize(complete); err != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}
	contact, err := c.GetRemoteVaultysID()
	if err != nil {
		return nil, abort(s, CodeHandshakeFailed)
	}
	cert, _ := c.GetCertificate()
	return &Result{Contact: contact, Certificate: cert, Session: s}, nil
}

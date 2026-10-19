package dockercontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"golang.org/x/sys/unix"
	"os"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

const controlOperatorProtocol = "sandbox-runtime.control-operator-observation.v1"

// Deployment bootstrap commitment; deliberately EMPTY in normal builds. Neither
// a Profile, key file nor operator statement may supply its own trust anchor.
// Explicit local diagnostic builds pin a fresh test-only key using -ldflags -X.
// No exported production constructor consumes this held component.
var controlOperatorKeyPin string

type controlOperatorRequest struct {
	Protocol     string `json:"protocol"`
	Scope        string `json:"scope"`
	Run          string `json:"run"`
	Challenge    string `json:"challenge"`
	ProfileBytes string `json:"profile_bytes"`
	Profile      string `json:"profile"`
	Namespace    string `json:"namespace"`
	Intent       string `json:"intent"`
	Seal         string `json:"seal"`
	Root         string `json:"root"`
	Inventory    string `json:"inventory"`
	Volumes      string `json:"volumes"`
	Issued       int64  `json:"issued"`
	Expires      int64  `json:"expires"`
}
type controlOperatorReply struct {
	RequestDigest string `json:"request_digest"`
	Signature     []byte `json:"signature"`
}
type controlOperatorSession struct {
	mu       sync.Mutex
	key      ed25519.PublicKey
	request  controlOperatorRequest
	consumed bool
	deadline time.Time // monotonic process deadline, in addition to signed wall time
}

func operatorBytes(r controlOperatorRequest) []byte {
	data, _ := json.Marshal(r)
	return append([]byte(controlOperatorProtocol+"\x00"), data...)
}
func operatorRequestDigest(r controlOperatorRequest) string {
	d := sha256.Sum256(operatorBytes(r))
	return "sha256:" + hex.EncodeToString(d[:])
}
func newControlOperatorSession(key []byte, trustedPin string, r controlOperatorRequest) (*controlOperatorSession, error) {
	d := sha256.Sum256(key)
	if len(key) != ed25519.PublicKeySize || !controlDigest.MatchString(trustedPin) || "sha256:"+hex.EncodeToString(d[:]) != trustedPin {
		return nil, ErrInvalidCodingInventory
	}
	for _, v := range []string{r.ProfileBytes, r.Profile, r.Intent, r.Seal, r.Root, r.Inventory, r.Volumes} {
		if !controlDigest.MatchString(v) {
			return nil, ErrInvalidCodingInventory
		}
	}
	if raw, e := hex.DecodeString(r.Namespace); e != nil || len(raw) != 16 || hex.EncodeToString(raw) != r.Namespace {
		return nil, ErrInvalidCodingInventory
	}
	var nonce [64]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, ErrInvalidCodingInventory
	}
	now := time.Now()
	r.Protocol = controlOperatorProtocol
	r.Scope = "held-control-consumer-component"
	r.Run = hex.EncodeToString(nonce[:32])
	r.Challenge = hex.EncodeToString(nonce[32:])
	r.Issued = now.Unix()
	r.Expires = now.Add(120 * time.Second).Unix()
	return &controlOperatorSession{key: bytes.Clone(key), request: r, deadline: now.Add(120 * time.Second)}, nil
}
func (s *controlOperatorSession) accept(data []byte) error {
	if s == nil || len(data) > 2048 {
		return ErrInvalidCodingInventory
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Every attempt consumes this session, including malformed/invalid replies.
	if s.consumed {
		return ErrInvalidCodingInventory
	}
	s.consumed = true
	var v controlOperatorReply
	if json.Unmarshal(data, &v) != nil {
		return ErrInvalidCodingInventory
	}
	canonical, _ := json.Marshal(v)
	if !bytes.Equal(data, canonical) || !s.alive() || v.RequestDigest != operatorRequestDigest(s.request) || len(v.Signature) != ed25519.SignatureSize || !ed25519.Verify(s.key, operatorBytes(s.request), v.Signature) {
		return ErrInvalidCodingInventory
	}
	return nil
}
func (s *controlOperatorSession) alive() bool {
	return s != nil && time.Now().Before(s.deadline) && time.Now().Unix() >= s.request.Issued && time.Now().Unix() < s.request.Expires
}

type preparedControlAdmission struct {
	observer *controlStorageUnixObserver
	probe    *controlstorage.SourceProbe
	session  *controlOperatorSession
	consumed bool
	mu       sync.Mutex
}

// Only this collector supplies observation values. Canonical Profile review by
// itself cannot authorize storage. Preparation never writes to the Store root.
func prepareControlAdmission(ctx context.Context, endpoint codingBoundUnixEndpoint, b controlStorageBinding, document []byte, bootstrap *os.File) (*preparedControlAdmission, error) {
	if bootstrap == nil {
		return nil, ErrInvalidCodingInventory
	}
	defer bootstrap.Close()
	if ctx == nil || ctx.Err() != nil || b.boundary == nil || controlTrustStorageHeld(b) || b.validate() != nil || endpoint.path != controlStorageSocketTarget {
		return nil, ErrInvalidCodingInventory
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	// Re-derive the complete authority inside the constructor. Exported review
	// structs (including their claimed byte hash) never substitute for source.
	derived, e := phase6security.ReviewControlConsumerBoundary(document)
	if e != nil || executionDigest("boundary", derived) != executionDigest("boundary", b.boundary) {
		return nil, ErrInvalidCodingInventory
	}
	b.boundary = &derived
	b.profileSource = &derived.Review
	key, e := readControlOperatorKey(ctx, bootstrap)
	if e != nil {
		return nil, e
	}
	o, e := openControlStorageUnixObserver(endpoint, b, nil)
	if e != nil {
		return nil, e
	}
	p := &preparedControlAdmission{observer: o}
	ok := false
	defer func() {
		if !ok {
			_ = p.Close()
		}
	}()
	a, e := readControlStorageInventory(ctx, o.api, b)
	if e != nil {
		return nil, e
	}
	b.sourceVolumes, e = readSourceVolumeBinding(ctx, o.api, b)
	if e != nil {
		return nil, e
	}
	o.binding = b
	p.probe, e = controlstorage.ProbeSourceBound(ctx, controlStorageTarget, b.Storage, b.Backend, b.SourceSealDigest, b.sourceVolumes)
	if e != nil {
		return nil, e
	}
	root, e := p.probe.Observe(ctx)
	if e != nil {
		return nil, e
	}
	z, e := readControlStorageInventory(ctx, o.api, b)
	if e != nil || a != z {
		return nil, ErrInvalidCodingInventory
	}
	end, e := p.probe.Observe(ctx)
	if e != nil || root != end {
		return nil, ErrInvalidCodingInventory
	}
	r := controlOperatorRequest{ProfileBytes: b.boundary.ProfileBytesDigest, Profile: b.Storage.ProfileDigest, Namespace: b.Storage.Namespace, Intent: b.profileSource.Source.IntentDigest, Seal: b.SourceSealDigest, Root: root, Inventory: a, Volumes: b.sourceVolumes}
	p.session, e = newControlOperatorSession(key, controlOperatorKeyPin, r)
	if e != nil {
		return nil, e
	}
	ok = true
	return p, nil
}
func (p *preparedControlAdmission) Request() ([]byte, error) {
	if p == nil {
		return nil, ErrInvalidCodingInventory
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.consumed || !p.session.alive() {
		return nil, ErrInvalidCodingInventory
	}
	return json.Marshal(p.session.request)
}
func (p *preparedControlAdmission) Open(ctx context.Context, reply []byte, initialize bool) (*sourceBoundControlStorage, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalidCodingInventory
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.consumed {
		return nil, ErrInvalidCodingInventory
	}
	p.consumed = true
	success := false
	defer func() {
		if !success {
			p.closeLocked()
		}
	}()
	if p.session.accept(reply) != nil {
		return nil, ErrInvalidCodingInventory
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	o := p.observer
	b := o.binding
	r := p.session.request
	root, e := p.probe.Observe(ctx)
	if e != nil || root != r.Root {
		return nil, ErrInvalidCodingInventory
	}
	inv, e := readControlStorageInventory(ctx, o.api, b)
	if e != nil || inv != r.Inventory || !p.session.alive() {
		return nil, ErrInvalidCodingInventory
	}
	root, e = p.probe.Observe(ctx)
	if e != nil || root != r.Root {
		return nil, ErrInvalidCodingInventory
	}
	if initialize {
		o.store, e = controlstorage.InitializeSourceBound(ctx, controlStorageTarget, b.Storage, b.Backend, b.SourceSealDigest, b.sourceVolumes)
	} else {
		o.store, e = controlstorage.OpenSourceBound(controlStorageTarget, b.Storage, b.Backend, b.SourceSealDigest, b.sourceVolumes)
	}
	if e != nil {
		return nil, e
	}
	observation, e := observeControlStorage(ctx, o.api, o.store, b)
	if e != nil || observation.RootDigest != r.Root || observation.InventoryDigest != r.Inventory || !p.session.alive() {
		_ = o.store.Close()
		o.store = nil
		return nil, controlstorage.ErrUncertain
	}
	_ = p.probe.Close()
	p.probe = nil
	p.observer = nil
	success = true
	return &sourceBoundControlStorage{observer: o, admission: p.session}, nil
}
func (p *preparedControlAdmission) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}
func (p *preparedControlAdmission) closeLocked() error {
	p.consumed = true
	if p.probe != nil {
		_ = p.probe.Close()
		p.probe = nil
	}
	if p.observer != nil {
		if p.observer.store != nil {
			_ = p.observer.store.Close()
		}
		_ = p.observer.api.Close()
		p.observer.transport.CloseIdleConnections()
		p.observer = nil
	}
	return nil
}

// The owned, one-shot pipe is an explicit diagnostic bootstrap channel, not a
// credential path declared by the production Profile. Its bytes are untrusted;
// only the independent build commitment authenticates the public key.
func readControlOperatorKey(ctx context.Context, pipe *os.File) ([]byte, error) {
	if pipe == nil {
		return nil, ErrInvalidCodingInventory
	}
	defer pipe.Close()
	if ctx == nil || ctx.Err() != nil || !controlDigest.MatchString(controlOperatorKeyPin) {
		return nil, ErrInvalidCodingInventory
	}
	fd := int(pipe.Fd())
	var st unix.Stat_t
	flags, e := unix.FcntlInt(pipe.Fd(), unix.F_GETFL, 0)
	if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return nil, ErrInvalidCodingInventory
	}
	// This function is the exclusive reader/owner of the supplied pipe. Poll then
	// a bounded read cannot wait for further bytes; no other reader can drain it.
	data := make([]byte, 0, ed25519.PublicKeySize+1)
	for {
		if ctx.Err() != nil {
			return nil, ErrInvalidCodingInventory
		}
		polls := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP}}
		n, e := unix.Poll(polls, 20)
		if e == unix.EINTR {
			continue
		}
		if e != nil || polls[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return nil, ErrInvalidCodingInventory
		}
		if n == 0 {
			continue
		}
		var buf [33]byte
		n, e = unix.Read(fd, buf[:])
		if e == unix.EINTR || e == unix.EAGAIN {
			continue
		}
		if e != nil {
			return nil, ErrInvalidCodingInventory
		}
		if n == 0 {
			break
		}
		data = append(data, buf[:n]...)
		if len(data) > ed25519.PublicKeySize {
			return nil, ErrInvalidCodingInventory
		}
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, ErrInvalidCodingInventory
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != controlOperatorKeyPin {
		return nil, ErrInvalidCodingInventory
	}
	return data, nil
}

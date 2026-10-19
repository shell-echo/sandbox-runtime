package dockercontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func operatorTestSession(t *testing.T) (*controlOperatorSession, ed25519.PrivateKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(pub)
	d := executionTestDigest("1")
	s, e := newControlOperatorSession(pub, "sha256:"+hex.EncodeToString(sum[:]), controlOperatorRequest{ProfileBytes: d, Profile: d, Namespace: strings.Repeat("a", 32), Intent: d, Seal: d, Root: d, Inventory: d, Volumes: d})
	if e != nil {
		t.Fatal(e)
	}
	return s, key
}
func signedOperatorReply(s *controlOperatorSession, k ed25519.PrivateKey) []byte {
	v := controlOperatorReply{operatorRequestDigest(s.request), ed25519.Sign(k, operatorBytes(s.request))}
	data, _ := json.Marshal(v)
	return data
}
func TestControlOperatorFreshSingleUseAndPinnedAuthority(t *testing.T) {
	for _, name := range []string{"valid", "self-key", "changed-profile", "changed-root", "changed-inventory", "changed-run", "changed-protocol", "expired-wall", "expired-monotonic", "future", "malformed", "unknown-field", "cross-session"} {
		t.Run(name, func(t *testing.T) {
			s, k := operatorTestSession(t)
			reply := signedOperatorReply(s, k)
			switch name {
			case "self-key":
				_, wrong, _ := ed25519.GenerateKey(rand.Reader)
				reply = signedOperatorReply(s, wrong)
			case "changed-profile":
				s.request.Profile = executionTestDigest("2")
			case "changed-root":
				s.request.Root = executionTestDigest("2")
			case "changed-inventory":
				s.request.Inventory = executionTestDigest("2")
			case "changed-run":
				s.request.Run = strings.Repeat("0", 64)
			case "changed-protocol":
				s.request.Protocol = "other"
			case "expired-wall":
				s.request.Expires = time.Now().Unix()
				reply = signedOperatorReply(s, k)
			case "expired-monotonic":
				s.deadline = time.Now().Add(-time.Second)
			case "future":
				s.request.Issued = time.Now().Add(time.Minute).Unix()
				reply = signedOperatorReply(s, k)
			case "malformed":
				reply = []byte("{")
			case "unknown-field":
				reply = append(reply[:len(reply)-1], []byte(",\"extra\":true}")...)
			case "cross-session":
				z, e := newControlOperatorSession(s.key, func() string { d := sha256.Sum256(s.key); return "sha256:" + hex.EncodeToString(d[:]) }(), s.request)
				if e != nil {
					t.Fatal(e)
				}
				s = z
			}
			e := s.accept(reply)
			if (e == nil) != (name == "valid") {
				t.Fatal("signature result", e)
			}
			if s.accept(reply) == nil {
				t.Fatal("attempt replay")
			}
		})
	}
	s, _ := operatorTestSession(t)
	if _, e := newControlOperatorSession(s.key, executionTestDigest("9"), s.request); e == nil {
		t.Fatal("untrusted key")
	}
	if _, e := newControlOperatorSession(s.key, "", s.request); e == nil {
		t.Fatal("missing deployment pin")
	}
}

func TestOperatorBootstrapPipeIsBoundedAndPinned(t *testing.T) {
	// Global bootstrap commitment is normally immutable; this sequential test
	// temporarily installs one local fixture key, never concurrent with callers.
	s, _ := operatorTestSession(t)
	d := sha256.Sum256(s.key)
	old := controlOperatorKeyPin
	controlOperatorKeyPin = "sha256:" + hex.EncodeToString(d[:])
	defer func() { controlOperatorKeyPin = old }()
	for _, name := range []string{"valid", "short", "long", "wrong", "not-closed", "cancel"} {
		t.Run(name, func(t *testing.T) {
			r, w, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			data := append([]byte{}, s.key...)
			switch name {
			case "short":
				data = data[:31]
			case "long":
				data = append(data, 0)
			case "wrong":
				data[0] ^= 1
			}
			if _, e := w.Write(data); e != nil {
				t.Fatal(e)
			}
			if name != "not-closed" {
				_ = w.Close()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			if name == "cancel" {
				cancel()
			}
			_, e = readControlOperatorKey(ctx, r)
			if (e == nil) != (name == "valid") {
				t.Fatal("bootstrap", e)
			}
			if _, e := r.Stat(); e == nil {
				t.Fatal("owned descriptor leaked")
			}
		})
	}
	f, e := os.CreateTemp(t.TempDir(), "regular")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := readControlOperatorKey(t.Context(), f); e == nil {
		t.Fatal("regular file accepted")
	}
}

package controldelivery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/shell-echo/sandbox-runtime/internal/controlbootstrap"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6process"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"reflect"
	"sync/atomic"
	"time"
)

var consumed atomic.Bool

// Run consumes this process's single delivery session. FD3 authentication is
// represented only by an opaque verified credential, never a raw public key.
func Run(ctx context.Context, credential *controlbootstrap.Credential) (err error) {
	stage := "session"
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", ErrUnavailable, stage)
		}
	}()
	if consumed.Swap(true) || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	stage = "credential"
	review, e := credential.Review()
	if e != nil || phase6fdloader.ControlStartupProtocol(review.Bootstrap.Target) == "" {
		return ErrUnavailable
	}
	stage = "startup-binding"
	channel, binding, e := phase6fdloader.OpenDeliveryChannel(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer channel.Close()
	var selected phase6security.ControlServiceIdentityV1
	for _, s := range review.Services {
		if s.Launch.Target == review.Bootstrap.Target {
			selected = s
		}
	}
	stage = "process"
	process, e := phase6process.ObservePID1(ctx)
	if e != nil || phase6process.Verify(process, selected, "role") != nil {
		return ErrUnavailable
	}
	stage = "probe"
	probe, e := phase6process.ObserveProbe(ctx, selected.Launch.ProbeDigest, false)
	if e != nil {
		return ErrUnavailable
	}
	var source *phase6process.SourceObservation
	var session *dockercontrol.ControlSourceSession
	if phase6security.ControlObservesSource(review.Bootstrap.Target) {
		stage = "source"
		doc, err := credential.Document()
		if err != nil {
			return ErrUnavailable
		}
		defer clear(doc)
		session, e = dockercontrol.PrepareControlSource(ctx, doc, binding)
		if e != nil {
			return ErrUnavailable
		}
		defer session.Close()
		v, err := session.Observe(ctx)
		if err != nil {
			return ErrUnavailable
		}
		source = &v
	}
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return ErrUnavailable
	}
	protocol, scope := Domain(review.Bootstrap.Target)
	challenge := Challenge{protocol, scope, binding, review.Bootstrap.KeyID, review.ProfileBytesDigest, review.ProfileDigest, selected.Principal.Name, hex.EncodeToString(nonce[:]), start.Unix(), start.Unix() + 120, process, probe, source}
	if _, e := ValidateChallenge(challenge, review, time.Now()); e != nil {
		return ErrUnavailable
	}
	stage = "challenge"
	raw, e := json.Marshal(challenge)
	if e != nil || phase6fdloader.WriteOutput(ctx, raw, MaxFrame) != nil {
		return ErrUnavailable
	}
	stage = "reply"
	raw, e = channel.ReadReply(ctx, MaxFrame)
	if e != nil {
		return ErrUnavailable
	}
	var reply Reply
	if phase6fdloader.DecodeCanonical(raw, &reply) != nil {
		return ErrUnavailable
	}
	stage = "signature"
	signed, e := SigningBytes(challenge, reply)
	if e != nil || !credential.VerifySignature(signed, reply.Signature) {
		return ErrUnavailable
	}
	stage = "reobserve"
	after, e := phase6process.ObservePID1(ctx)
	if e != nil || !reflect.DeepEqual(process, after) {
		return ErrUnavailable
	}
	afterProbe, e := phase6process.ObserveProbe(ctx, selected.Launch.ProbeDigest, false)
	if e != nil || probe != afterProbe || ctx.Err() != nil || time.Since(start) >= 120*time.Second {
		return ErrUnavailable
	}
	if _, e := ValidateChallenge(challenge, review, time.Now()); e != nil {
		return ErrUnavailable
	}
	if session != nil {
		stage = "source-reobserve"
		v, err := session.Observe(ctx)
		if err != nil || source == nil || !reflect.DeepEqual(v, *source) {
			return ErrUnavailable
		}
	}
	stage = "receipt"
	raw, e = json.Marshal(Receipt{protocol, scope, "held-not-a-permit", reply.ChallengeDigest, reply.OperatorObservationDigest})
	if e != nil || phase6fdloader.WriteOutput(ctx, raw, MaxFrame) != nil {
		return ErrUnavailable
	}
	return nil // Caller must still exit held; this is never service admission.
}

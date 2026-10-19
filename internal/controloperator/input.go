// Package controloperator is the host-only signer for a held process delivery
// ceremony. It neither creates grants nor opens the Control Store. Only an
// explicit local daemon and already-created, unprivileged container are used.
package controloperator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Input struct {
	Host         string `json:"host"`
	DaemonID     string `json:"daemon_id"`
	ContainerID  string `json:"container_id"`
	ConfigVolume string `json:"config_volume"`
	Profile      string `json:"profile"`
	Envelope     string `json:"envelope"`
	PrivateKey   string `json:"private_key"`
	Archive      string `json:"archive"`
	Index        string `json:"index"`
	Manifest     string `json:"manifest"`
	Config       string `json:"config"`
	RoleBinary   string `json:"role_binary"`
	LoaderBinary string `json:"loader_binary"`
	ProbeBinary  string `json:"probe_binary"`
}
type inputs struct {
	input     Input
	document  []byte
	envelope  phase6fdloader.Envelope
	review    phase6security.ControlBootstrapReview
	service   phase6security.ControlServiceIdentityV1
	key       ed25519.PrivateKey
	selected  ocispec.Descriptor
	config    ocispec.Image
	documents phase6security.ImageDescriptorDocuments
}

func load(ctx context.Context, path string) (*inputs, error) {
	fail := controldelivery.ErrUnavailable
	raw, e := secretfile.Read(path, 64<<10)
	var in Input
	if e != nil || phase6fdloader.DecodeCanonical(raw, &in) != nil || !strings.HasPrefix(in.Host, "unix:///") || !filepath.IsAbs(strings.TrimPrefix(in.Host, "unix://")) || strings.ContainsAny(in.Host, "?\x00#") || in.DaemonID == "" || in.ConfigVolume == "" || len(in.ContainerID) != 64 {
		return nil, fail
	}
	a := &inputs{input: in}
	a.document, e = secretfile.Read(in.Profile, 4<<20)
	if e != nil {
		return nil, fail
	}
	a.review, e = phase6security.ReviewControlBootstrap(a.document)
	if e != nil || phase6fdloader.ControlStartupProtocol(a.review.Bootstrap.Target) == "" {
		return nil, fail
	}
	for _, s := range a.review.Services {
		if s.Launch.Target == a.review.Bootstrap.Target {
			a.service = s
		}
	}
	key, e := secretfile.Read(in.PrivateKey, ed25519.PrivateKeySize)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fail
	}
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:32])
	defer clear(derived)
	if string(derived) != string(key) || controldelivery.Digest(key[32:]) != a.review.Bootstrap.KeyDigest {
		return nil, fail
	}
	raw, e = secretfile.Read(in.Envelope, phase6fdloader.MaxEnvelopeBytes)
	if e != nil || json.Unmarshal(raw, &a.envelope) != nil {
		return nil, fail
	}
	defer clear(raw)
	ev := a.envelope
	if ev.ContainerID != in.ContainerID || ev.Target != a.review.Bootstrap.Target || phase6fdloader.DecodeCanonical(raw, &a.envelope) != nil || ev.Validate(phase6fdloader.Expected{RunID: ev.RunID, Target: ev.Target, Nonce: ev.Nonce, ContainerHostname: in.ContainerID[:12]}) != nil || string(ev.Files[0].Data) != string(key[32:]) {
		a.envelope.Destroy()
		return nil, fail
	}
	var docs phase6security.ImageDescriptorDocuments
	for _, v := range []struct {
		path string
		dst  *[]byte
	}{{in.Index, &docs.Index}, {in.Manifest, &docs.Manifest}, {in.Config, &docs.Config}} {
		*v.dst, e = secretfile.Read(v.path, 4<<20)
		if e != nil {
			return nil, fail
		}
	}
	if _, e := phase6security.ReviewControlServiceImage(a.document, a.service.Principal.Name, in.Archive, docs); e != nil {
		return nil, fail
	}
	a.documents = docs
	var index ocispec.Index
	if json.Unmarshal(docs.Index, &index) != nil || json.Unmarshal(docs.Config, &a.config) != nil {
		return nil, fail
	}
	for _, d := range index.Manifests {
		if d.Digest.String() == a.service.Principal.ImageSelectedManifestDigest {
			a.selected = d
		}
	}
	if a.selected.Platform == nil || a.selected.Size != int64(len(docs.Manifest)) {
		return nil, fail
	}
	for _, v := range []struct{ path, want string }{{in.RoleBinary, a.service.Launch.ExecutableDigest}, {in.LoaderBinary, a.service.Launch.LoaderDigest}, {in.ProbeBinary, a.service.Launch.ProbeDigest}} {
		path, want := v.path, v.want
		if ctx.Err() != nil {
			return nil, fail
		}
		b, e := executable(path)
		if e != nil || controldelivery.Digest(b) != want {
			clear(b)
			return nil, fail
		}
		clear(b)
	}
	if ctx.Err() != nil {
		return nil, fail
	}
	a.key = append(ed25519.PrivateKey(nil), key...)
	return a, nil
}
func executable(path string) ([]byte, error) {
	fail := controldelivery.ErrUnavailable
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0555 || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Size() < 1 || before.Size() > 128<<20 {
		return nil, fail
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, fail
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !os.SameFile(before, st) {
		return nil, fail
	}
	b, e := io.ReadAll(io.LimitReader(f, (128<<20)+1))
	after, ae := os.Lstat(path)
	if e != nil || ae != nil || !os.SameFile(st, after) || st.Size() != int64(len(b)) || after.Size() != st.Size() || after.Mode() != st.Mode() {
		clear(b)
		return nil, fail
	}
	return b, nil
}

//go:build darwin || linux

package dockercontrol

import (
	"context"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	"testing"
)

func TestExecutionSourceBindingJoin(t *testing.T) {
	source := newSourceControlFixture(t).b
	b := executionTestBinding(t)
	d, _ := b.Template.Digest()
	source.Storage.TemplateDigest = d
	b.Storage = source.Storage
	b.DaemonDigest, b.DaemonEnvironmentDigest = source.Daemon.IdentityDigest, source.Daemon.EnvironmentDigest
	b.EndpointScopeDigest = source.EndpointScopeDigest
	endpoint := codingBoundUnixEndpoint{path: controlStorageSocketTarget, scopeDigest: b.EndpointScopeDigest}
	if bindExecutionSource(endpoint, b, source) != nil {
		t.Fatal("matching held bindings refused")
	}
	if _, rawSatisfies := any(new(controlstorage.Store)).(executionStateStorage); rawSatisfies {
		t.Fatal("raw Store satisfies source-owner port")
	}
	for name, change := range map[string]func(*executionBinding, *controlStorageBinding, *codingBoundUnixEndpoint){
		"profile": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			b.Storage.ProfileDigest = executionTestDigest("0")
		},
		"principal": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			b.Storage.ControlPrincipalDigest = executionTestDigest("0")
		},
		"namespace": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			b.Storage.Namespace = "0123456789abcdef0123456789abcdef"
			b.Storage.StorageID = "control-execution-" + b.Storage.Namespace
		},
		"uid": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) { b.Storage.UID++ },
		"gid": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) { b.Storage.GID++ },
		"template": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			b.Storage.TemplateDigest = executionTestDigest("0")
		},
		"layout": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			b.Storage.Layout.OtherScopesUnallocatedBytes--
		},
		"daemon": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			b.DaemonDigest = executionTestDigest("0")
		},
		"environment": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			b.DaemonEnvironmentDigest = executionTestDigest("0")
		},
		"endpoint": func(b *executionBinding, _ *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			b.EndpointScopeDigest = executionTestDigest("0")
		},
		"socket scope": func(_ *executionBinding, _ *controlStorageBinding, e *codingBoundUnixEndpoint) {
			e.scopeDigest = executionTestDigest("0")
		},
		"socket path": func(_ *executionBinding, _ *controlStorageBinding, e *codingBoundUnixEndpoint) {
			e.path = "/var/run/docker.sock"
		},
		"platform": func(_ *executionBinding, s *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			s.Daemon.Platform = "linux/amd64"
		},
		"legacy": func(_ *executionBinding, s *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			s.SourceSealDigest = ""
			s.SourceSocket = ""
		},
		"derived volume input": func(_ *executionBinding, s *controlStorageBinding, _ *codingBoundUnixEndpoint) {
			s.sourceVolumes = executionTestDigest("0")
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad, s, e := b.clone(), source, endpoint
			change(&bad, &s, &e)
			if bindExecutionSource(e, bad, s) == nil {
				t.Fatal("cross-binding drift accepted")
			}
			// The environment has no selected source socket. Invalid input must fail
			// during the pure join, without opening or initializing any root.
			if l, err := openSourceExecutionLedger(t.Context(), e, bad, s, true); err == nil || l != nil {
				t.Fatal("invalid input reached an owner")
			}
		})
	}
}

func TestExecutionLedgerFailedLoadReleasesOwnerWithoutRepair(t *testing.T) {
	b := executionTestBinding(t)
	root := executionTestRoot(t)
	s, err := controlstorage.Initialize(t.Context(), root, b.Storage, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if l, err := loadExecutionLedger(t.Context(), &executionFileFixture{s}, b, false); err == nil || l != nil {
		t.Fatal("missing ledger initialized on reopen")
	}
	// Failure releases the lock, but retains the permanent namespace marker.
	s, err = controlstorage.Open(root, b.Storage)
	if err != nil {
		t.Fatal("failed load leaked owner", err)
	}
	snap, err := s.ReadState(t.Context(), b.digest()[7:39])
	if err != nil || snap.Found {
		t.Fatal("failed load repaired state")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if l, err := initializeExecutionLedger(t.Context(), root, b, func(context.Context) error { return nil }); err == nil || l != nil {
		t.Fatal("failed load reset namespace")
	}
}

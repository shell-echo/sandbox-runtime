package dockercontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
)

type scriptedCodingInfo struct {
	values []system.Info
	errAt  int
	calls  int
}

func (s *scriptedCodingInfo) Info(ctx context.Context, _ client.InfoOptions) (client.SystemInfoResult, error) {
	s.calls++
	if ctx.Err() != nil || s.errAt == s.calls || s.calls > len(s.values) {
		return client.SystemInfoResult{}, ErrInvalidCodingDaemon
	}
	return client.SystemInfoResult{Info: s.values[s.calls-1]}, nil
}

func codingInfoFixture() system.Info {
	return system.Info{ID: "opaque:daemon-id", OSType: "linux", Architecture: "aarch64",
		DockerRootDir: "/var/lib/docker", ServerVersion: "29.7.2"}
}

func TestCodingDaemonIdentityAndEnvironmentAreSeparate(t *testing.T) {
	scope := testControlDigest("7")
	base, err := projectCodingDaemonInfo(codingInfoFixture(), scope)
	if err != nil || base.Platform != "linux/arm64/v8" ||
		!controlDigest.MatchString(base.IdentityDigest) || !controlDigest.MatchString(base.EnvironmentDigest) {
		t.Fatalf("base daemon projection = %#v, %v", base, err)
	}
	changedID := codingInfoFixture()
	changedID.ID = "different-daemon"
	other, err := projectCodingDaemonInfo(changedID, scope)
	if err != nil || other.IdentityDigest == base.IdentityDigest || other.EnvironmentDigest != base.EnvironmentDigest {
		t.Fatalf("ID was not separate identity: %#v, %v", other, err)
	}
	changedVersion := codingInfoFixture()
	changedVersion.ServerVersion = "29.7.3"
	upgraded, err := projectCodingDaemonInfo(changedVersion, scope)
	if err != nil || upgraded.IdentityDigest != base.IdentityDigest ||
		upgraded.EnvironmentDigest == base.EnvironmentDigest {
		t.Fatalf("version drift impersonated replacement daemon: %#v, %v", upgraded, err)
	}
	changedRoot := codingInfoFixture()
	changedRoot.DockerRootDir = "/different-docker-root"
	moved, err := projectCodingDaemonInfo(changedRoot, scope)
	if err != nil || moved.IdentityDigest != base.IdentityDigest || moved.EnvironmentDigest == base.EnvironmentDigest {
		t.Fatalf("root drift impersonated replacement daemon: %#v, %v", moved, err)
	}
	otherScope, err := projectCodingDaemonInfo(codingInfoFixture(), testControlDigest("8"))
	if err != nil || otherScope.IdentityDigest == base.IdentityDigest || otherScope.EnvironmentDigest != base.EnvironmentDigest {
		t.Fatalf("endpoint/deployment scope did not bind identity: %#v, %v", otherScope, err)
	}
	amd64 := codingInfoFixture()
	amd64.Architecture = "x86_64"
	x86, err := projectCodingDaemonInfo(amd64, scope)
	if err != nil || x86.Platform != "linux/amd64" || x86.EnvironmentDigest == base.EnvironmentDigest {
		t.Fatalf("x86_64 mapping = %#v, %v", x86, err)
	}
}

func TestCodingDaemonObservationRejectsInvalidOrMissingFields(t *testing.T) {
	scope := testControlDigest("7")
	for name, change := range map[string]func(*system.Info){
		"empty ID":      func(info *system.Info) { info.ID = "" },
		"control ID":    func(info *system.Info) { info.ID = "daemon\nother" },
		"unknown arch":  func(info *system.Info) { info.Architecture = "arm64" },
		"non-linux":     func(info *system.Info) { info.OSType = "windows" },
		"empty version": func(info *system.Info) { info.ServerVersion = "" },
		"relative root": func(info *system.Info) { info.DockerRootDir = "var/lib/docker" },
		"nonclean root": func(info *system.Info) { info.DockerRootDir = "/var/lib/../docker" },
		"empty root":    func(info *system.Info) { info.DockerRootDir = "" },
	} {
		t.Run(name, func(t *testing.T) {
			info := codingInfoFixture()
			change(&info)
			if _, err := projectCodingDaemonInfo(info, scope); !errors.Is(err, ErrInvalidCodingDaemon) {
				t.Fatalf("invalid daemon admitted: %v", err)
			}
		})
	}
	if _, err := projectCodingDaemonInfo(codingInfoFixture(), "unbound"); !errors.Is(err, ErrInvalidCodingDaemon) {
		t.Fatalf("unbound endpoint admitted: %v", err)
	}
}

func TestCodingDaemonReadOnlyInventoryBracketRejectsDriftAndErrors(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	for name, script := range map[string]func(*scriptedCodingInfo){
		"same daemon":       func(_ *scriptedCodingInfo) {},
		"ID changed":        func(reader *scriptedCodingInfo) { reader.values[1].ID = "other-daemon" },
		"version changed":   func(reader *scriptedCodingInfo) { reader.values[1].ServerVersion = "29.7.3" },
		"root changed":      func(reader *scriptedCodingInfo) { reader.values[1].DockerRootDir = "/different" },
		"second Info error": func(reader *scriptedCodingInfo) { reader.errAt = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			reader := &scriptedCodingInfo{values: []system.Info{codingInfoFixture(), codingInfoFixture()}}
			script(reader)
			inventoryCalls := 0
			observation, err := ObserveCodingDaemonAround(context.Background(), reader, binding,
				func(context.Context) error { inventoryCalls++; return nil })
			if name == "same daemon" {
				if err != nil || observation.IdentityDigest != binding.DaemonDigest || inventoryCalls != 1 || reader.calls != 2 {
					t.Fatalf("same-client bracket = %v, inventory=%d, Info=%d", err, inventoryCalls, reader.calls)
				}
			} else if !errors.Is(err, ErrInvalidCodingDaemon) || inventoryCalls != 1 {
				t.Fatalf("drift became absence: %v, inventory=%d", err, inventoryCalls)
			}
		})
	}
	reader := &scriptedCodingInfo{values: []system.Info{codingInfoFixture(), codingInfoFixture()}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ObserveCodingDaemonAround(ctx, reader, binding,
		func(context.Context) error { t.Fatal("cancelled inventory ran"); return nil }); !errors.Is(err, ErrInvalidCodingDaemon) || reader.calls != 0 {
		t.Fatalf("cancelled observation = %v, Info calls=%d", err, reader.calls)
	}
	reader = &scriptedCodingInfo{values: []system.Info{codingInfoFixture(), codingInfoFixture()}}
	if _, err := ObserveCodingDaemonAround(context.Background(), reader, binding,
		func(context.Context) error { return errors.New("inventory failed") }); !errors.Is(err, ErrInvalidCodingDaemon) || reader.calls != 1 {
		t.Fatalf("inventory failure became absence: %v, Info calls=%d", err, reader.calls)
	}
}

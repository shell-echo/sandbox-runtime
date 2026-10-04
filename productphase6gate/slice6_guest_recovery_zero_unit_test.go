//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSlice6GuestDockerZeroReceiptIsPrivateAndNotAcceptance(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	run, err := root.newRun(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer run.close()
	implicit := [2]string{strings.Repeat("b", 64), strings.Repeat("c", 64)}
	vaultID := strings.Repeat("f", 64)
	originCalls := 0
	originProbe := func(_ context.Context, limit int, stdin []byte, command ...string) ([]byte, error, bool) {
		if stdin != nil {
			t.Fatal("origin probe supplied stdin")
		}
		index := originCalls
		originCalls++
		if index == 0 {
			if limit != 512 || len(command) != 4 || command[0] != "inspect" || command[1] != "--format" ||
				command[2] != slice6GuestRecoveryVaultMountFormat || command[3] != vaultID {
				t.Fatal("origin Docker projection drift")
			}
			return []byte(vaultID + "|" + run.id + "\n" + implicit[0] + "|/vault/file\n" +
				implicit[1] + "|/vault/logs\n"), nil, false
		}
		if index > 2 || limit != 256 || len(command) != 5 || command[0] != "volume" ||
			command[1] != "inspect" || command[2] != "--format" ||
			command[3] != slice6GuestRecoveryAnonymousVolumeFormat || command[4] != implicit[index-1] {
			t.Fatal("origin anonymous volume projection drift")
		}
		return []byte("{\"com.docker.volume.anonymous\":\"\"}\n"), nil, false
	}
	origin, err := run.captureGuestRecoveryImplicitOriginWithProbe(t.Context(), vaultID, originProbe)
	if err != nil || originCalls != 3 || run.verifyGuestRecoveryImplicitOrigin(origin) != nil {
		t.Fatalf("private implicit-volume origin unavailable: %v", err)
	}
	calls := 0
	probe := func(_ context.Context, limit int, stdin []byte, command ...string) ([]byte, error, bool) {
		if limit != 512 || stdin != nil || calls >= 5 {
			t.Fatal("Docker-zero probe escaped bounded whitelist")
		}
		index := calls
		calls++
		if index < 3 {
			if len(command) < 3 || command[0] != []string{"ps", "network", "volume"}[index] {
				t.Fatal("wrong Docker-zero resource class")
			}
			return nil, nil, false
		}
		if len(command) != 3 || command[0] != "volume" || command[1] != "inspect" ||
			command[2] != implicit[index-3] {
			t.Fatal("wrong exact implicit volume")
		}
		return []byte("Error: no such volume: " + command[2] + "\n"), errors.New("not found"), false
	}
	precleanup := "sha256:" + strings.Repeat("d", 64)
	receipt, err := run.proveGuestRecoveryDockerZeroWithProbe(t.Context(), precleanup, origin, probe)
	if err != nil || calls != 5 || receipt.Disposition != "docker_zero_component" ||
		run.verifyGuestRecoveryDockerZeroRaw(receipt) != nil {
		t.Fatalf("private Docker-zero component receipt unavailable: %v", err)
	}
	calls = 0
	if _, err := run.proveGuestRecoveryDockerZeroWithProbe(t.Context(), precleanup, origin, probe); err == nil {
		t.Fatal("duplicate Docker-zero receipt replaced the first")
	}
	wrong := receipt
	wrong.PrecleanupDigest = "sha256:" + strings.Repeat("e", 64)
	if run.verifyGuestRecoveryDockerZeroRaw(wrong) == nil {
		t.Fatal("Docker-zero receipt rebound to another precleanup proof")
	}
	wrongOrigin := origin
	wrongOrigin.FileVolumeID = strings.Repeat("e", 64)
	if _, err := run.proveGuestRecoveryDockerZeroWithProbe(t.Context(), precleanup, wrongOrigin, probe); err == nil {
		t.Fatal("Docker-zero receipt accepted a caller-spliced implicit volume ID")
	}
	labelPath := filepath.Join(rootPath, run.id, "guest-zero-origin-file-volume.label")
	labelOriginal, err := os.ReadFile(labelPath)
	if err != nil {
		t.Fatal(err)
	}
	labelFile, err := os.OpenFile(labelPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := labelFile.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	if err := labelFile.Close(); err != nil {
		t.Fatal(err)
	}
	if run.verifyGuestRecoveryDockerZeroRaw(receipt) == nil {
		t.Fatal("Docker-zero accepted tampered original anonymous-volume label")
	}
	labelFile, err = os.OpenFile(labelPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := labelFile.WriteAt(labelOriginal, 0); err != nil {
		t.Fatal(err)
	}
	if err := labelFile.Close(); err != nil {
		t.Fatal(err)
	}
	if run.verifyGuestRecoveryDockerZeroRaw(receipt) != nil {
		t.Fatal("restored same-inode origin raw failed readback")
	}
	path := filepath.Join(rootPath, run.id, "guest-zero-containers.stdout")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("Docker-zero raw file not private")
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("unexpected-id\n")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if run.verifyGuestRecoveryDockerZeroRaw(receipt) == nil {
		t.Fatal("nonzero Docker class accepted after same-inode tamper")
	}
}

func TestSlice6GuestVaultOriginRejectsUnknownLabelsAndMounts(t *testing.T) {
	validLabel := []byte("{\"com.docker.volume.anonymous\":\"\"}\n")
	if !slice6GuestRecoveryAnonymousVolumeLabels(validLabel) {
		t.Fatal("Docker anonymous volume's empty-valued label rejected")
	}
	for _, raw := range [][]byte{
		[]byte("{}\n"),
		[]byte("{\"com.docker.volume.anonymous\":\"\",\"other\":\"value\"}\n"),
		[]byte("{\"com.docker.volume.anonymous\":\"\"}"),
		[]byte("not-json\n"),
	} {
		if slice6GuestRecoveryAnonymousVolumeLabels(raw) {
			t.Fatal("unknown or noncanonical anonymous-volume metadata accepted")
		}
	}
	runID, vaultID := strings.Repeat("a", 32), strings.Repeat("f", 64)
	fileID, logsID := strings.Repeat("b", 64), strings.Repeat("c", 64)
	valid := []byte(vaultID + "|" + runID + "\n" + fileID + "|/vault/file\n" + logsID + "|/vault/logs\n")
	if _, err := slice6ParseGuestRecoveryVaultMounts(valid, runID, vaultID); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte(vaultID + "|" + strings.Repeat("d", 32) + "\n" + fileID + "|/vault/file\n" + logsID + "|/vault/logs\n"),
		[]byte(vaultID + "|" + runID + "\n" + fileID + "|/vault/file\n" + fileID + "|/vault/logs\n"),
		[]byte(vaultID + "|" + runID + "\n" + fileID + "|/vault/file\n" + logsID + "|/vault/logs\n" + logsID + "|/extra\n"),
	} {
		if _, err := slice6ParseGuestRecoveryVaultMounts(raw, runID, vaultID); err == nil {
			t.Fatal("Vault run, identity or exact two mounts drift accepted")
		}
	}
}

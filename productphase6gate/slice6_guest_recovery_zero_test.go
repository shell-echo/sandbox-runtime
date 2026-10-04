//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

type slice6GuestRecoveryDockerZeroReceipt struct {
	Protocol, RunID, PrecleanupDigest, Disposition string
	StartedUTC, FinishedUTC                        string
	OriginDigest                                   string
	ImplicitVolumeIDs                              [2]string
	RawSHA256                                      [5]string
}

type slice6GuestRecoveryImplicitOrigin struct {
	Protocol, RunID, VaultID   string
	FileVolumeID, LogsVolumeID string
	RawSHA256                  string
	VolumeLabelsSHA256         [2]string
}

const slice6GuestRecoveryVaultMountFormat = `{{.Id}}|{{index .Config.Labels "io.github.shell-echo.sandbox-runtime.phase6-slice6-run"}}{{range .Mounts}}{{if eq .Type "volume"}}{{printf "\n%s|%s" .Name .Destination}}{{end}}{{end}}`
const slice6GuestRecoveryAnonymousVolumeFormat = `{{json .Labels}}`

func slice6GuestRecoveryAnonymousVolumeLabels(raw []byte) bool {
	if len(raw) < 3 || len(raw) > 256 || !bytes.HasSuffix(raw, []byte("\n")) {
		return false
	}
	var labels map[string]string
	trimmed := bytes.TrimSuffix(raw, []byte("\n"))
	if json.Unmarshal(trimmed, &labels) != nil || len(labels) != 1 {
		return false
	}
	canonical, err := json.Marshal(labels)
	if err != nil || !bytes.Equal(trimmed, canonical) {
		return false
	}
	_, anonymous := labels["com.docker.volume.anonymous"]
	return anonymous
}

func slice6GuestRecoveryOriginDigest(origin slice6GuestRecoveryImplicitOrigin) string {
	return slice6ReceiptSHA256([]byte(origin.RawSHA256 + "|" + origin.VolumeLabelsSHA256[0] + "|" + origin.VolumeLabelsSHA256[1]))
}

func slice6ParseGuestRecoveryVaultMounts(raw []byte, runID, vaultID string) ([2]string, error) {
	var ids [2]string
	if len(raw) < 1 || len(raw) > 512 || !bytes.HasSuffix(raw, []byte("\n")) ||
		bytes.ContainsRune(raw, '\r') || bytes.ContainsRune(raw, '\x00') {
		return ids, fmt.Errorf("Vault mount projection framing: %w", phase6guestreceipt.ErrUnavailable)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		return ids, fmt.Errorf("Vault mount projection line count %d: %w", len(lines), phase6guestreceipt.ErrUnavailable)
	}
	if lines[0] != vaultID+"|"+runID {
		return ids, fmt.Errorf("Vault mount projection identity: %w", phase6guestreceipt.ErrUnavailable)
	}
	for _, line := range lines[1:] {
		parts := strings.Split(line, "|")
		if len(parts) != 2 || len(parts[0]) != 64 || !lowerHexSlice6(parts[0]) {
			return [2]string{}, phase6guestreceipt.ErrUnavailable
		}
		switch parts[1] {
		case "/vault/file":
			if ids[0] != "" {
				return [2]string{}, phase6guestreceipt.ErrUnavailable
			}
			ids[0] = parts[0]
		case "/vault/logs":
			if ids[1] != "" {
				return [2]string{}, phase6guestreceipt.ErrUnavailable
			}
			ids[1] = parts[0]
		default:
			return [2]string{}, phase6guestreceipt.ErrUnavailable
		}
	}
	if ids[0] == "" || ids[1] == "" || ids[0] == ids[1] {
		return [2]string{}, phase6guestreceipt.ErrUnavailable
	}
	return ids, nil
}

func (run *slice6ReceiptEvidenceRun) captureGuestRecoveryImplicitOrigin(ctx context.Context,
	vaultID string) (slice6GuestRecoveryImplicitOrigin, error) {
	return run.captureGuestRecoveryImplicitOriginWithProbe(ctx, vaultID, slice6DockerBounded)
}

func (run *slice6ReceiptEvidenceRun) captureGuestRecoveryImplicitOriginWithProbe(ctx context.Context,
	vaultID string, probe slice6GuestRecoveryDockerProbe) (slice6GuestRecoveryImplicitOrigin, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || run.check() != nil ||
		len(vaultID) != 64 || !lowerHexSlice6(vaultID) || probe == nil {
		return slice6GuestRecoveryImplicitOrigin{}, phase6guestreceipt.ErrUnavailable
	}
	raw, commandErr, overflow := probe(ctx, 512, nil,
		"inspect", "--format", slice6GuestRecoveryVaultMountFormat, vaultID)
	defer clear(raw)
	if commandErr != nil || overflow || ctx.Err() != nil {
		return slice6GuestRecoveryImplicitOrigin{}, fmt.Errorf("Vault mount projection unavailable: %w", phase6guestreceipt.ErrUnavailable)
	}
	ids, err := slice6ParseGuestRecoveryVaultMounts(raw, run.id, vaultID)
	if err != nil {
		return slice6GuestRecoveryImplicitOrigin{}, fmt.Errorf("Vault mount projection invalid: %w", err)
	}
	if err := run.writeV2BoundedPrivateFile("guest-zero-origin.inspect", raw, 512, true); err != nil {
		return slice6GuestRecoveryImplicitOrigin{}, err
	}
	origin := slice6GuestRecoveryImplicitOrigin{Protocol: "sandbox-runtime.phase6-guest-vault-origin.v1",
		RunID: run.id, VaultID: vaultID, FileVolumeID: ids[0], LogsVolumeID: ids[1], RawSHA256: slice6ReceiptSHA256(raw)}
	for index, id := range ids {
		labelRaw, labelErr, labelOverflow := probe(ctx, 256, nil, "volume", "inspect", "--format",
			slice6GuestRecoveryAnonymousVolumeFormat, id)
		if labelErr != nil || labelOverflow || ctx.Err() != nil || !slice6GuestRecoveryAnonymousVolumeLabels(labelRaw) {
			category := "unexpected_marker"
			if labelErr != nil {
				category = "docker_error"
			}
			if labelOverflow {
				category = "overflow"
			}
			if ctx.Err() != nil {
				category = "context"
			}
			clear(labelRaw)
			return slice6GuestRecoveryImplicitOrigin{}, fmt.Errorf("Vault anonymous volume %d projection %s (length %d): %w", index, category, len(labelRaw), phase6guestreceipt.ErrUnavailable)
		}
		name := []string{"guest-zero-origin-file-volume.label", "guest-zero-origin-logs-volume.label"}[index]
		if err := run.writeV2BoundedPrivateFile(name, labelRaw, 256, false); err != nil {
			clear(labelRaw)
			return slice6GuestRecoveryImplicitOrigin{}, err
		}
		origin.VolumeLabelsSHA256[index] = slice6ReceiptSHA256(labelRaw)
		clear(labelRaw)
	}
	encoded, err := json.Marshal(origin)
	if err != nil || len(encoded) > 1024 ||
		run.writeV2BoundedPrivateFile("guest-zero-origin-receipt.json", encoded, 1024, false) != nil ||
		run.verifyGuestRecoveryImplicitOrigin(origin) != nil {
		return slice6GuestRecoveryImplicitOrigin{}, fmt.Errorf("Vault origin readback unavailable: %w", phase6guestreceipt.ErrUnavailable)
	}
	return origin, nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryImplicitOrigin(origin slice6GuestRecoveryImplicitOrigin) error {
	if run == nil || run.check() != nil || origin.Protocol != "sandbox-runtime.phase6-guest-vault-origin.v1" ||
		origin.RunID != run.id || len(origin.VaultID) != 64 || !lowerHexSlice6(origin.VaultID) {
		return phase6guestreceipt.ErrUnavailable
	}
	raw, err := run.readFile("guest-zero-origin.inspect", 512)
	if err != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	defer clear(raw)
	ids, err := slice6ParseGuestRecoveryVaultMounts(raw, run.id, origin.VaultID)
	if err != nil || ids[0] != origin.FileVolumeID || ids[1] != origin.LogsVolumeID ||
		slice6ReceiptSHA256(raw) != origin.RawSHA256 {
		return phase6guestreceipt.ErrUnavailable
	}
	for index, name := range []string{"guest-zero-origin-file-volume.label", "guest-zero-origin-logs-volume.label"} {
		labelRaw, labelErr := run.readFile(name, 256)
		if labelErr != nil || !slice6GuestRecoveryAnonymousVolumeLabels(labelRaw) ||
			slice6ReceiptSHA256(labelRaw) != origin.VolumeLabelsSHA256[index] {
			clear(labelRaw)
			return phase6guestreceipt.ErrUnavailable
		}
		clear(labelRaw)
	}
	encoded, err := run.readFile("guest-zero-origin-receipt.json", 1024)
	if err != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	defer clear(encoded)
	canonical, err := json.Marshal(origin)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

var slice6GuestRecoveryDockerZeroRawNames = [5]string{
	"guest-zero-containers.stdout", "guest-zero-networks.stdout", "guest-zero-volumes.stdout",
	"guest-zero-implicit-1.inspect", "guest-zero-implicit-2.inspect",
}

func (run *slice6ReceiptEvidenceRun) writeV2GuestZeroRaw(name string, raw []byte) error {
	allowed := false
	for _, candidate := range slice6GuestRecoveryDockerZeroRawNames {
		allowed = allowed || name == candidate
	}
	if !allowed {
		return phase6guestreceipt.ErrUnavailable
	}
	return run.writeV2BoundedPrivateFile(name, raw, 512, true)
}

func (run *slice6ReceiptEvidenceRun) proveGuestRecoveryDockerZero(ctx context.Context,
	precleanupDigest string, origin slice6GuestRecoveryImplicitOrigin) (slice6GuestRecoveryDockerZeroReceipt, error) {
	return run.proveGuestRecoveryDockerZeroWithProbe(ctx, precleanupDigest, origin, slice6DockerBounded)
}

type slice6GuestRecoveryDockerProbe func(context.Context, int, []byte, ...string) ([]byte, error, bool)

func (run *slice6ReceiptEvidenceRun) proveGuestRecoveryDockerZeroWithProbe(ctx context.Context,
	precleanupDigest string, origin slice6GuestRecoveryImplicitOrigin,
	probe slice6GuestRecoveryDockerProbe) (slice6GuestRecoveryDockerZeroReceipt, error) {
	implicit := [2]string{origin.FileVolumeID, origin.LogsVolumeID}
	if ctx == nil || ctx.Err() != nil || run == nil || run.check() != nil ||
		probe == nil || run.verifyGuestRecoveryImplicitOrigin(origin) != nil ||
		!guestRevokeFixtureDigestGate(precleanupDigest) ||
		len(implicit[0]) != 64 || !lowerHexSlice6(implicit[0]) ||
		len(implicit[1]) != 64 || !lowerHexSlice6(implicit[1]) || implicit[0] == implicit[1] {
		return slice6GuestRecoveryDockerZeroReceipt{}, errors.New("Guest recovery Docker-zero target invalid")
	}
	started := time.Now().UTC()
	args := [5][]string{
		{"ps", "-aq", "--no-trunc", "--filter", "label=" + slice6RunLabel + "=" + run.id},
		{"network", "ls", "-q", "--no-trunc", "--filter", "label=" + slice6RunLabel + "=" + run.id},
		{"volume", "ls", "-q", "--filter", "label=" + slice6RunLabel + "=" + run.id},
		{"volume", "inspect", implicit[0]},
		{"volume", "inspect", implicit[1]},
	}
	var digests [5]string
	for index, command := range args {
		raw, commandErr, overflow := probe(ctx, 512, nil, command...)
		if overflow || ctx.Err() != nil ||
			(index < 3 && (commandErr != nil || len(raw) != 0)) ||
			(index >= 3 && (commandErr == nil ||
				!bytes.Contains(bytes.ToLower(raw), []byte(": no such volume")) ||
				!bytes.Contains(raw, []byte(implicit[index-3])))) {
			clear(raw)
			return slice6GuestRecoveryDockerZeroReceipt{}, errors.New("Guest recovery exact Docker resource absence unconfirmed")
		}
		if err := run.writeV2GuestZeroRaw(slice6GuestRecoveryDockerZeroRawNames[index], raw); err != nil {
			clear(raw)
			return slice6GuestRecoveryDockerZeroReceipt{}, err
		}
		digests[index] = slice6ReceiptSHA256(raw)
		clear(raw)
	}
	finished := time.Now().UTC()
	receipt := slice6GuestRecoveryDockerZeroReceipt{Protocol: "sandbox-runtime.phase6-guest-docker-zero.v1",
		RunID: run.id, PrecleanupDigest: precleanupDigest, Disposition: "docker_zero_component",
		StartedUTC: started.Format(time.RFC3339Nano), FinishedUTC: finished.Format(time.RFC3339Nano),
		OriginDigest: slice6GuestRecoveryOriginDigest(origin), ImplicitVolumeIDs: implicit, RawSHA256: digests}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > 2048 {
		return slice6GuestRecoveryDockerZeroReceipt{}, phase6guestreceipt.ErrUnavailable
	}
	if err := run.writeV2GuestZeroReceiptFile("guest-zero-receipt.json", encoded); err != nil {
		return slice6GuestRecoveryDockerZeroReceipt{}, err
	}
	if err := run.verifyGuestRecoveryDockerZeroRaw(receipt); err != nil {
		return slice6GuestRecoveryDockerZeroReceipt{}, err
	}
	return receipt, nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryDockerZeroRaw(
	receipt slice6GuestRecoveryDockerZeroReceipt) error {
	if run == nil || run.check() != nil || receipt.RunID != run.id ||
		receipt.Protocol != "sandbox-runtime.phase6-guest-docker-zero.v1" ||
		receipt.Disposition != "docker_zero_component" ||
		!guestRevokeFixtureDigestGate(receipt.PrecleanupDigest) ||
		!guestRevokeFixtureDigestGate(receipt.OriginDigest) ||
		len(receipt.ImplicitVolumeIDs[0]) != 64 || !lowerHexSlice6(receipt.ImplicitVolumeIDs[0]) ||
		len(receipt.ImplicitVolumeIDs[1]) != 64 || !lowerHexSlice6(receipt.ImplicitVolumeIDs[1]) ||
		receipt.ImplicitVolumeIDs[0] == receipt.ImplicitVolumeIDs[1] {
		return phase6guestreceipt.ErrUnavailable
	}
	originRaw, err := run.readFile("guest-zero-origin-receipt.json", 1024)
	if err != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	var origin slice6GuestRecoveryImplicitOrigin
	decodeErr := json.Unmarshal(originRaw, &origin)
	clear(originRaw)
	if decodeErr != nil || run.verifyGuestRecoveryImplicitOrigin(origin) != nil ||
		receipt.OriginDigest != slice6GuestRecoveryOriginDigest(origin) ||
		receipt.ImplicitVolumeIDs != [2]string{origin.FileVolumeID, origin.LogsVolumeID} {
		return phase6guestreceipt.ErrUnavailable
	}
	started, startErr := time.Parse(time.RFC3339Nano, receipt.StartedUTC)
	finished, finishErr := time.Parse(time.RFC3339Nano, receipt.FinishedUTC)
	if startErr != nil || finishErr != nil || !finished.After(started) {
		return phase6guestreceipt.ErrUnavailable
	}
	for index, name := range slice6GuestRecoveryDockerZeroRawNames {
		raw, err := run.readFile(name, 512)
		if err != nil || slice6ReceiptSHA256(raw) != receipt.RawSHA256[index] ||
			(index < 3 && len(raw) != 0) ||
			(index >= 3 && (!bytes.Contains(bytes.ToLower(raw), []byte(": no such volume")) ||
				!bytes.Contains(raw, []byte(receipt.ImplicitVolumeIDs[index-3])))) {
			clear(raw)
			return phase6guestreceipt.ErrUnavailable
		}
		clear(raw)
	}
	encoded, err := run.readFile("guest-zero-receipt.json", 2048)
	if err != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	defer clear(encoded)
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

func (run *slice6ReceiptEvidenceRun) writeV2GuestZeroReceiptFile(name string, raw []byte) error {
	if name != "guest-zero-receipt.json" {
		return phase6guestreceipt.ErrUnavailable
	}
	return run.writeV2BoundedPrivateFile(name, raw, 2048, false)
}

func (run *slice6ReceiptEvidenceRun) writeV2BoundedPrivateFile(name string, raw []byte, limit int, allowEmpty bool) error {
	if run == nil || run.check() != nil || len(raw) > limit || (!allowEmpty && len(raw) == 0) {
		return phase6guestreceipt.ErrUnavailable
	}
	run.mu.Lock()
	if run.check() != nil || run.closed {
		run.mu.Unlock()
		return phase6guestreceipt.ErrUnavailable
	}
	file, err := run.createPrivateFileLocked(name)
	run.mu.Unlock()
	if err != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	written, writeErr := file.Write(raw)
	syncErr := run.syncFile(file)
	closeErr := file.Close()
	if written != len(raw) || writeErr != nil || syncErr != nil || closeErr != nil ||
		run.syncDir(run.fd) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	observed, err := run.readFile(name, limit)
	defer clear(observed)
	if err != nil || !bytes.Equal(observed, raw) {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

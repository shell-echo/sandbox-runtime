//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

var slice6GuestRecoveryExactOriginZeroRawNames = [3]string{
	"guest-zero-original-guest-product.inspect",
	"guest-zero-original-guest-runtime.inspect",
	"guest-zero-original-vault.inspect",
}

type slice6GuestRecoveryExactOriginZeroReceipt struct {
	Protocol, RunID, PrecleanupDigest, DockerZeroDigest string
	CreatedNetworksDigest, VaultOriginDigest            string
	Disposition, StartedUTC, FinishedUTC                string
	OriginalIDs                                         [3]string
	RawSHA256                                           [3]string
}

func slice6GuestRecoveryExactOriginMissing(raw []byte, id string, network bool) bool {
	if len(id) != 64 || !lowerHexSlice6(id) || len(raw) < 1 || len(raw) > 512 {
		return false
	}
	if network {
		return bytes.Equal(raw, []byte("[]\nError response from daemon: network "+id+" not found\n"))
	}
	return bytes.Equal(raw, []byte("[]\nerror: no such object: "+id+"\n"))
}

func (run *slice6ReceiptEvidenceRun) guestRecoveryOriginalIDs(
	input slice6GuestRecoveryPrecleanupInput) ([3]string, error) {
	if run == nil || run.verifyGuestRecoveryCreatedNetworks(input) != nil ||
		run.verifyGuestRecoveryImplicitOrigin(input.VaultOrigin) != nil {
		return [3]string{}, phase6guestreceipt.ErrUnavailable
	}
	raw, err := run.readFile(slice6GuestRecoveryCreatedReceiptRaw, 512)
	if err != nil {
		return [3]string{}, err
	}
	defer clear(raw)
	var created slice6GuestRecoveryCreatedNetworks
	if json.Unmarshal(raw, &created) != nil {
		return [3]string{}, phase6guestreceipt.ErrUnavailable
	}
	return [3]string{created.GuestProductID, created.GuestRuntimeID, input.VaultOrigin.VaultID}, nil
}

// This remains a Docker-only component receipt. The formal E launcher must
// also bind non-Docker terminal state before any accepted disposition.
func (run *slice6ReceiptEvidenceRun) proveGuestRecoveryExactOriginZero(ctx context.Context,
	input slice6GuestRecoveryPrecleanupInput, dockerZero slice6GuestRecoveryDockerZeroReceipt,
	probe slice6GuestRecoveryDockerProbe) (slice6GuestRecoveryExactOriginZeroReceipt, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || run.check() != nil || probe == nil ||
		run.verifyGuestRecoveryDockerZeroRaw(dockerZero) != nil {
		return slice6GuestRecoveryExactOriginZeroReceipt{}, phase6guestreceipt.ErrUnavailable
	}
	precleanupDigest, err := run.verifyGuestRecoveryPrecleanupCore(input)
	if err != nil || precleanupDigest != dockerZero.PrecleanupDigest ||
		dockerZero.OriginDigest != slice6GuestRecoveryOriginDigest(input.VaultOrigin) {
		return slice6GuestRecoveryExactOriginZeroReceipt{}, errors.New("Guest E exact zero does not bind precleanup/original Vault")
	}
	ids, err := run.guestRecoveryOriginalIDs(input)
	if err != nil {
		return slice6GuestRecoveryExactOriginZeroReceipt{}, err
	}
	encodedDockerZero, err := json.Marshal(dockerZero)
	if err != nil {
		return slice6GuestRecoveryExactOriginZeroReceipt{}, err
	}
	started := time.Now().UTC()
	receipt := slice6GuestRecoveryExactOriginZeroReceipt{
		Protocol: "sandbox-runtime.phase6-guest-exact-origin-zero.v1", RunID: run.id,
		PrecleanupDigest: precleanupDigest, DockerZeroDigest: slice6ReceiptSHA256(encodedDockerZero),
		CreatedNetworksDigest: input.CreatedNetworksDigest,
		VaultOriginDigest:     slice6GuestRecoveryOriginDigest(input.VaultOrigin),
		Disposition:           "exact_docker_origin_zero_component", OriginalIDs: ids,
		StartedUTC: started.Format(time.RFC3339Nano),
	}
	for index, id := range ids {
		command := []string{"network", "inspect", id}
		if index == 2 {
			command = []string{"inspect", id}
		}
		raw, commandErr, overflow := probe(ctx, 512, nil, command...)
		if commandErr == nil || overflow || ctx.Err() != nil ||
			!slice6GuestRecoveryExactOriginMissing(raw, id, index < 2) {
			clear(raw)
			return slice6GuestRecoveryExactOriginZeroReceipt{}, errors.New("Guest E original network/Vault identity absence unconfirmed")
		}
		if err := run.writeV2BoundedPrivateFile(slice6GuestRecoveryExactOriginZeroRawNames[index],
			raw, 512, false); err != nil {
			clear(raw)
			return slice6GuestRecoveryExactOriginZeroReceipt{}, err
		}
		receipt.RawSHA256[index] = slice6ReceiptSHA256(raw)
		clear(raw)
	}
	receipt.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > 2048 ||
		run.writeV2BoundedPrivateFile("guest-zero-exact-origins.json", encoded, 2048, false) != nil ||
		run.verifyGuestRecoveryExactOriginZeroRaw(input, dockerZero, receipt) != nil {
		return slice6GuestRecoveryExactOriginZeroReceipt{}, phase6guestreceipt.ErrUnavailable
	}
	return receipt, nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryExactOriginZeroRaw(
	input slice6GuestRecoveryPrecleanupInput, dockerZero slice6GuestRecoveryDockerZeroReceipt,
	receipt slice6GuestRecoveryExactOriginZeroReceipt) error {
	if run == nil || run.check() != nil || receipt.Protocol != "sandbox-runtime.phase6-guest-exact-origin-zero.v1" ||
		receipt.RunID != run.id || receipt.Disposition != "exact_docker_origin_zero_component" ||
		receipt.PrecleanupDigest != dockerZero.PrecleanupDigest ||
		receipt.CreatedNetworksDigest != input.CreatedNetworksDigest ||
		receipt.VaultOriginDigest != slice6GuestRecoveryOriginDigest(input.VaultOrigin) ||
		run.verifyGuestRecoveryDockerZeroRaw(dockerZero) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	ids, err := run.guestRecoveryOriginalIDs(input)
	if err != nil || ids != receipt.OriginalIDs {
		return phase6guestreceipt.ErrUnavailable
	}
	precleanupDigest, err := run.verifyGuestRecoveryPrecleanupCore(input)
	if err != nil || precleanupDigest != receipt.PrecleanupDigest {
		return phase6guestreceipt.ErrUnavailable
	}
	encodedDockerZero, err := json.Marshal(dockerZero)
	if err != nil || slice6ReceiptSHA256(encodedDockerZero) != receipt.DockerZeroDigest {
		return phase6guestreceipt.ErrUnavailable
	}
	started, startErr := time.Parse(time.RFC3339Nano, receipt.StartedUTC)
	finished, finishErr := time.Parse(time.RFC3339Nano, receipt.FinishedUTC)
	if startErr != nil || finishErr != nil || !finished.After(started) {
		return phase6guestreceipt.ErrUnavailable
	}
	for index, name := range slice6GuestRecoveryExactOriginZeroRawNames {
		raw, err := run.readFile(name, 512)
		if err != nil || slice6ReceiptSHA256(raw) != receipt.RawSHA256[index] ||
			!slice6GuestRecoveryExactOriginMissing(raw, ids[index], index < 2) {
			clear(raw)
			return phase6guestreceipt.ErrUnavailable
		}
		clear(raw)
	}
	encoded, err := run.readFile("guest-zero-exact-origins.json", 2048)
	if err != nil {
		return err
	}
	defer clear(encoded)
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

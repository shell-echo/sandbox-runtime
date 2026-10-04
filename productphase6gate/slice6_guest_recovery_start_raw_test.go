//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryStartRaw(binding slice6GuestRecoveryRawBinding) error {
	name := slice6GuestRecoveryStartInspectName(binding.Process)
	if run == nil || run.check() != nil || binding.RunID != run.id || name == "" ||
		!guestRevokeFixtureDigestGate(binding.StartInspectSHA256) {
		return phase6guestreceipt.ErrUnavailable
	}
	raw, err := run.readFile(name, 640)
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) < 2 || !bytes.HasSuffix(raw, []byte("\n")) ||
		bytes.Count(raw, []byte("\n")) != 1 || slice6ReceiptSHA256(raw) != binding.StartInspectSHA256 {
		return errors.New("Guest B start Docker observation raw unavailable")
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 10 || fields[0] != binding.ContainerID ||
		fields[1] != binding.ImageID || fields[2] != binding.ImageRef ||
		fields[3] != run.id || fields[4] != "none" || fields[5] != "false" ||
		fields[6] != "true" || fields[7] != strconv.Itoa(binding.PID) ||
		fields[8] != binding.StartedAt || fields[9] != "false" {
		return errors.New("Guest B start Docker running identity drift")
	}
	return nil
}

package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var ErrBodyTooLarge = errors.New("provider request body too large")

const (
	MaxCreateRequestBytes             int64 = 1 << 20
	MaxRestoreRequestBytes            int64 = 1 << 20
	MaxDesiredStateRequestBytes       int64 = 64 << 10
	MaxLeaseRequestBytes              int64 = 64 << 10
	MaxExecRequestBytes               int64 = 256 << 10
	MaxCancelExecRequestBytes         int64 = 64 << 10
	MaxRuntimeSessionOpenRequestBytes int64 = 64 << 10
	MaxBrowserSessionOpenRequestBytes int64 = 64 << 10
	MaxArtifactStagingRequestBytes    int64 = 64 << 10
	MaxSnapshotRequestBytes           int64 = 256 << 10
	MaxTerminateRequestBytes          int64 = 64 << 10
)

// DecodeStrict decodes one bounded Provider API JSON document. Contract-level
// required-field and cross-field validation remains a separate admission step.
func DecodeStrict(reader io.Reader, maxBytes int64, destination any) error {
	if reader == nil {
		return errors.New("provider request body is required")
	}
	if maxBytes <= 0 {
		return errors.New("provider request body limit must be positive")
	}

	body, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return fmt.Errorf("read provider request body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return ErrBodyTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode provider request body: %w", err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode provider request trailer: %w", err)
	}
	return errors.New("provider request body contains multiple JSON values")
}

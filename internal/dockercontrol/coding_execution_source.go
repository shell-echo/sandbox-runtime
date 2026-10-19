//go:build darwin || linux

package dockercontrol

import "context"

func (*sourceBoundControlStorage) executionSourceOwner() {}

// This checks the two held component bindings before any socket/filesystem I/O.
// It does not validate a full Profile or manufacture operator/dispatch authority.
func bindExecutionSource(endpoint codingBoundUnixEndpoint, b executionBinding, source controlStorageBinding) error {
	if b.validate() != nil || source.validate() != nil || source.SourceSealDigest == "" || source.sourceVolumes != "" ||
		endpoint.path != controlStorageSocketTarget || endpoint.scopeDigest != source.EndpointScopeDigest ||
		b.Storage != source.Storage || b.DaemonDigest != source.Daemon.IdentityDigest ||
		b.DaemonEnvironmentDigest != source.Daemon.EnvironmentDigest || b.EndpointScopeDigest != source.EndpointScopeDigest ||
		b.Template.Image.Platform != source.Daemon.Platform {
		return ErrInvalidReceiptState
	}
	return nil
}

// openSourceExecutionLedger is the only non-test ledger constructor. Both source
// and Docker sessions stay private and owned until callbacks drain and Close
// releases them. Full Profile/operator source-access admission remains held;
// the current real callers are explicit integration fixtures, not a command.
func openSourceExecutionLedger(ctx context.Context, endpoint codingBoundUnixEndpoint, b executionBinding, source controlStorageBinding, initialize bool) (*executionLedger, error) {
	if ctx == nil || ctx.Err() != nil || bindExecutionSource(endpoint, b, source) != nil {
		return nil, ErrInvalidReceiptState
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	s, err := openSourceBoundControlStorage(ctx, endpoint, source, initialize)
	if err != nil {
		return nil, err
	}
	return loadExecutionLedger(ctx, s, b, initialize)
}

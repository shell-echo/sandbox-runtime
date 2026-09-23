package workloadtlsagent

import (
	"context"
	"crypto"
	"errors"
	"testing"
)

func TestHandshakeSignerHonorsCancellationBeforeSocketWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	signer := &RemoteSigner{client: &Client{}, generation: 1, context: ctx}
	_, err := signer.Sign(nil, make([]byte, 32), crypto.SHA256)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled handshake signer: %v", err)
	}
}

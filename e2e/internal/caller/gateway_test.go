package caller

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitForGatewayCloseConsumesQueuedFrames(t *testing.T) {
	closeErr := errors.New("websocket closed")
	reads := 0
	err := waitForGatewayClose(context.Background(), time.Second, func(context.Context) error {
		reads++
		if reads < 3 {
			return nil
		}
		return closeErr
	})
	if err != nil {
		t.Fatalf("waitForGatewayClose() error = %v", err)
	}
	if reads != 3 {
		t.Fatalf("read count = %d, want 3", reads)
	}
}

func TestWaitForGatewayCloseReportsOpenConnectionOnTimeout(t *testing.T) {
	started := make(chan struct{})
	err := waitForGatewayClose(context.Background(), 20*time.Millisecond, func(ctx context.Context) error {
		select {
		case <-started:
		case <-ctx.Done():
			return ctx.Err()
		default:
			close(started)
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if err == nil || err.Error() != "revoked Gateway connection remained open" {
		t.Fatalf("waitForGatewayClose() error = %v, want timeout error", err)
	}
}

func TestWaitForGatewayClosePreservesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitForGatewayClose(ctx, time.Second, func(readCtx context.Context) error {
		return readCtx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForGatewayClose() error = %v, want context cancellation", err)
	}
}

package roleprocess

import (
	"testing"
	"time"
)

func TestBrowserProbeOpenProducesValidExecutorAuthority(t *testing.T) {
	open, err := browserProbeOpen()
	if err != nil {
		t.Fatal(err)
	}
	if err := open.Validate(time.Now().UTC()); err != nil {
		t.Fatalf("browser probe authority is invalid: %v", err)
	}
}

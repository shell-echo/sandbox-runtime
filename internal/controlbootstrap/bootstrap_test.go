package controlbootstrap

import (
	"context"
	"os"
	"testing"
)

func TestBootstrapCannotSelfSelectPin(t *testing.T) {
	if publicKeyPin != "" {
		t.Fatal("normal build gained a trust root")
	}
	f, e := os.CreateTemp(t.TempDir(), "key")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Verify(context.Background(), []byte(`{"key_digest":"self-selected"}`), f); e == nil {
		t.Fatal("self supplied root accepted")
	}
	if _, e := f.Stat(); e == nil {
		t.Fatal("descriptor ownership not consumed")
	}
}

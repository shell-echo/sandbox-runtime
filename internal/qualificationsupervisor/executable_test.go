package qualificationsupervisor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestSupportedPlatform(t *testing.T) {
	for _, name := range []string{"darwin", "linux", "windows", "freebsd", "", "Darwin"} {
		if supportedPlatform(name) != (name == "darwin" || name == "linux") {
			t.Fatal(name)
		}
	}
}

type cancelReader struct{ cancel context.CancelFunc }

func (r cancelReader) Read(p []byte) (int, error) { r.cancel(); p[0] = 'x'; return 1, io.EOF }

func TestDigestBoundsAndCancellation(t *testing.T) {
	for _, size := range []int{65535, 65536, 65537} {
		_, n, err := digestReader(context.Background(), bytes.NewReader(bytes.Repeat([]byte{'x'}, size)), 65536)
		if size > 65536 {
			if !errors.Is(err, ErrExecutable) {
				t.Fatal(err)
			}
		} else if err != nil || n != int64(size) {
			t.Fatal(n, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, _, err := digestReader(ctx, cancelReader{cancel}, 10); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

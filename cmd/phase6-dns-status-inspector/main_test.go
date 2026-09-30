package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type shortStatusWriter struct{}

func (shortStatusWriter) Write([]byte) (int, error) { return 0, nil }

func TestFixedStatusReaderIsBoundedAndExact(t *testing.T) {
	input := []byte("Name:\tcoredns\nCapBnd:\t0000000000000400\n")
	var output bytes.Buffer
	if err := writeStatus(&output, bytes.NewReader(input)); err != nil || !bytes.Equal(output.Bytes(), input) {
		t.Fatalf("bounded exact status rejected: %v", err)
	}
	for _, input := range [][]byte{nil, bytes.Repeat([]byte("x"), maxStatusBytes+1)} {
		if err := writeStatus(io.Discard, bytes.NewReader(input)); !errors.Is(err, errInvalidStatus) {
			t.Fatal("invalid status accepted")
		}
	}
	if err := writeStatus(shortStatusWriter{}, bytes.NewReader([]byte("status"))); !errors.Is(err, errInvalidStatus) {
		t.Fatal("short output write accepted")
	}
}

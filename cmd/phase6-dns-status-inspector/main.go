// phase6-dns-status-inspector is a gate-only, fixed-purpose reader for the
// stock CoreDNS process status. It is not part of the DNS application image.
package main

import (
	"errors"
	"io"
	"os"
)

const maxStatusBytes = 64 << 10

var errInvalidStatus = errors.New("invalid CoreDNS process status")

func main() {
	if len(os.Args) != 1 {
		os.Exit(1)
	}
	file, err := os.Open("/proc/1/status")
	if err != nil {
		os.Exit(1)
	}
	defer file.Close()
	if writeStatus(os.Stdout, file) != nil {
		os.Exit(1)
	}
}

func writeStatus(output io.Writer, input io.Reader) error {
	if output == nil || input == nil {
		return errInvalidStatus
	}
	status, err := io.ReadAll(io.LimitReader(input, maxStatusBytes+1))
	if err != nil || len(status) < 1 || len(status) > maxStatusBytes {
		return errInvalidStatus
	}
	written, err := output.Write(status)
	if err != nil || written != len(status) {
		return errInvalidStatus
	}
	return nil
}

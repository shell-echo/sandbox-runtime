// Host-only operator command. Both inputs and transcript stay private files.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shell-echo/sandbox-runtime/internal/controloperator"
	"os"
	"os/signal"
	"syscall"
)

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("arguments")
	}
	out, e := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer out.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, e := controloperator.Run(ctx, os.Args[1])
	if writeErr := json.NewEncoder(out).Encode(result); writeErr != nil {
		return writeErr
	}
	return e
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("held Control process delivery verified; not a permit")
}

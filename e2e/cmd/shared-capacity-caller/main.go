package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/caller"
)

func main() {
	configPath := flag.String("config", "", "shared-capacity caller JSON configuration")
	flag.Parse()
	if *configPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "shared-capacity caller configuration required")
		os.Exit(2)
	}
	config, err := caller.LoadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "shared-capacity caller configuration invalid")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	stopInputCloser := make(chan struct{})
	defer close(stopInputCloser)
	go func() {
		select {
		case <-ctx.Done():
			_ = os.Stdin.Close()
		case <-stopInputCloser:
		}
	}()
	if err := caller.Run(ctx, config, os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "shared-capacity caller failed")
		os.Exit(1)
	}
}

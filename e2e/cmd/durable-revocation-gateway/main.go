package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	durablestack "github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/stack"
)

func main() {
	configPath := flag.String("config", "", "durable-revocation Gateway JSON configuration")
	flag.Parse()
	if *configPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-config is required")
		os.Exit(2)
	}
	config, err := durablestack.LoadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "durable-revocation Gateway configuration rejected")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	stack, err := durablestack.Open(ctx, config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "durable-revocation Gateway startup failed")
		os.Exit(1)
	}
	if err := errors.Join(stack.Run(ctx), stack.Close()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "durable-revocation Gateway stopped with an error")
		os.Exit(1)
	}
}

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/platform"
)

func main() {
	configPath := flag.String("config", "", "candidate caller JSON configuration")
	flag.Parse()
	if *configPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-config is required")
		os.Exit(2)
	}
	config, err := caller.LoadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	report, err := platform.Run(ctx, config)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil && err == nil {
		err = encodeErr
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

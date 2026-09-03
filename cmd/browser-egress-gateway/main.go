package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
)

func main() {
	if err := run(os.Args[1:], os.Getenv(gateway.ConfigEnvironment)); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "browser egress gateway failed")
		os.Exit(1)
	}
}

func run(arguments []string, encodedConfig string) error {
	if len(arguments) != 1 {
		return errors.New("exactly one mode is required")
	}
	config, err := gateway.DecodeConfig(encodedConfig)
	if err != nil {
		return err
	}
	switch arguments[0] {
	case "serve":
		server, err := gateway.NewSystem(config)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		return server.Serve(ctx)
	case "healthcheck":
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return gateway.Healthcheck(ctx, config)
	default:
		return errors.New("unsupported mode")
	}
}

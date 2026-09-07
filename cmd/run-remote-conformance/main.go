package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/remoteconformance"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run-remote-conformance", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options remoteconformance.Options
	flags.StringVar(&options.SourceRoot, "source-root", ".", "repository source root")
	flags.StringVar(&options.LockPath, "lock", "compatibility/sandbox-runtime/contract.lock.json", "relative or absolute Contract lock path")
	flags.StringVar(&options.Target, "target", "", "remote Provider HTTPS origin")
	flags.StringVar(&options.CAFile, "ca", "", "absolute Provider CA bundle path")
	flags.StringVar(&options.ClientCAFile, "client-ca", "", "absolute client identity CA bundle path")
	flags.StringVar(&options.ClientCert, "client-cert", "", "absolute mTLS client certificate path")
	flags.StringVar(&options.ClientKey, "client-key", "", "absolute mTLS client private key path")
	flags.StringVar(&options.DeniedClientCert, "denied-client-cert", "", "absolute chain-valid denied client certificate path")
	flags.StringVar(&options.DeniedClientKey, "denied-client-key", "", "absolute chain-valid denied client private key path")
	flags.StringVar(&options.ServerName, "server-name", "", "required TLS server name")
	flags.StringVar(&options.ProviderRevision, "provider-revision", "", "expected immutable Provider revision")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, err := remoteconformance.Run(ctx, options)
	if report.SchemaVersion != 0 {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if encodeErr := encoder.Encode(report); encodeErr != nil {
			_, _ = fmt.Fprintln(stderr, "run-remote-conformance: report_write_failed")
			return 1
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "run-remote-conformance:", err)
		return remoteconformance.ExitCode(err)
	}
	return 0
}

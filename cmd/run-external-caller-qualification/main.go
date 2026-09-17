package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationoperator"
)

func main() {
	var configuration qualificationoperator.RunConfiguration
	flag.StringVar(&configuration.SourceRoot, "source-root", "", "absolute sandbox-runtime source root")
	flag.StringVar(&configuration.RunRoot, "run-root", "", "new absolute run output root")
	flag.StringVar(&configuration.ProviderExecutable, "provider-executable", "", "absolute Provider executable")
	flag.StringVar(&configuration.OperatorExecutable, "operator-executable", "", "absolute operator executable")
	flag.StringVar(&configuration.CandidateDirectory, "candidate-directory", "", "absolute exact candidate artifact directory")
	flag.StringVar(&configuration.ProviderSourceRevision, "provider-source-revision", "", "immutable Provider/operator source revision")
	flag.StringVar(&configuration.ExternalSourceRevision, "external-source-revision", "", "immutable external-caller source revision")
	flag.StringVar(&configuration.DockerSocket, "docker-socket", "/var/run/docker.sock", "absolute Docker Engine Unix socket")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "qualification operator: unexpected positional arguments")
		os.Exit(64)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := qualificationoperator.Run(ctx, configuration)
	if err != nil {
		fmt.Fprintln(os.Stderr, "qualification operator:", err)
		os.Exit(1)
	}
	output := struct {
		CheckpointPath   string `json:"checkpoint_path"`
		CheckpointDigest string `json:"checkpoint_digest"`
	}{CheckpointPath: result.CheckpointPath, CheckpointDigest: result.CheckpointDigest}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, "qualification operator: output failed")
		os.Exit(74)
	}
}

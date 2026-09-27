package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
)

func main() {
	var input phase6rolecandidate.RecordInput
	flag.StringVar(&input.SourceRoot, "source-root", "", "absolute clean repository checkout")
	flag.StringVar(&input.Deployment, "deployment", "", "reviewed Slice 6 deployment name")
	flag.StringVar(&input.Platform, "platform", "", "linux/amd64 or linux/arm64/v8")
	flag.StringVar(&input.ImageID, "image", "", "immutable local Docker image digest")
	flag.StringVar(&input.OutputPath, "output", "", "new manifest in a private 0700 directory outside the checkout")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	manifest, err := phase6rolecandidate.Record(ctx, input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Phase 6 local role candidate not recorded: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("candidate=%s\ndeployment=%s\nbuild_target=%s\nimage=%s\nmanifest=%s\n",
		manifest.Classification, manifest.Source.Deployment, manifest.Source.BuildTarget,
		manifest.RuntimeStoreImageID, manifest.ManifestDigest)
}

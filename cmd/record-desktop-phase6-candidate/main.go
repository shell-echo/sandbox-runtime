package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
)

type imageInspection struct {
	ID           string `json:"Id"`
	Architecture string `json:"Architecture"`
	Variant      string `json:"Variant"`
	OS           string `json:"Os"`
	Config       struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func main() {
	var sourceRoot, platform, image, output string
	flag.StringVar(&sourceRoot, "source-root", "", "absolute repository root")
	flag.StringVar(&platform, "platform", "", "linux/amd64 or linux/arm64/v8")
	flag.StringVar(&image, "image", "", "local image reference to resolve")
	flag.StringVar(&output, "output", "", "absolute candidate manifest path outside the source tree")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(errors.New("unexpected positional arguments"))
	}
	root, err := filepath.Abs(sourceRoot)
	if err != nil || !filepath.IsAbs(sourceRoot) || !filepath.IsAbs(output) || image == "" {
		fail(errors.New("absolute source/output and image are required"))
	}
	relative, err := filepath.Rel(root, output)
	if err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		fail(errors.New("candidate manifest must be outside the source tree"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "image", "inspect", image)
	document, err := command.Output()
	if err != nil {
		fail(errors.New("inspect local candidate image"))
	}
	var inspections []imageInspection
	if json.Unmarshal(document, &inspections) != nil || len(inspections) != 1 {
		fail(errors.New("invalid local candidate image inspection"))
	}
	inspection := inspections[0]
	wantArchitecture, wantVariant := "amd64", ""
	if platform == "linux/arm64/v8" {
		wantArchitecture, wantVariant = "arm64", "v8"
	} else if platform != "linux/amd64" {
		fail(errors.New("unsupported candidate platform"))
	}
	if inspection.OS != "linux" || inspection.Architecture != wantArchitecture || (inspection.Variant != "" && inspection.Variant != wantVariant) || !strings.HasPrefix(inspection.ID, "sha256:") {
		fail(errors.New("candidate image platform or digest mismatch"))
	}
	candidate, err := desktopcandidate.New(root, platform, inspection.ID, inspection.ID)
	if err != nil {
		fail(err)
	}
	labels := inspection.Config.Labels
	if labels["io.github.shell-echo.sandbox-runtime.profile"] != candidate.ProfileID ||
		labels["org.opencontainers.image.revision"] != candidate.SourceRevision ||
		labels["org.opencontainers.image.base.digest"] != candidate.BaseImageDigest ||
		labels["io.github.shell-echo.sandbox-runtime.package-archive-set-digest"] != candidate.PackageArchiveSetDigest ||
		labels["io.github.shell-echo.sandbox-runtime.installed-set-digest"] != candidate.InstalledSetDigest {
		fail(errors.New("candidate image labels do not match source/build authority"))
	}
	if err := desktopcandidate.Save(output, candidate); err != nil {
		fail(err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "candidate=%s\nimage=%s\nmanifest=%s\n", candidate.Classification, candidate.ImageDigest, candidate.ManifestDigest)
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

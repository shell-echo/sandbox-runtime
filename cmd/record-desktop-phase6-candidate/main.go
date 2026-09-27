package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type imageInspection struct {
	ID           string           `json:"Id"`
	Descriptor   *imageDescriptor `json:"Descriptor"`
	Architecture string           `json:"Architecture"`
	Variant      string           `json:"Variant"`
	OS           string           `json:"Os"`
	Config       struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

type imageDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}

type containerInspection struct {
	ID                      string           `json:"Id"`
	Image                   string           `json:"Image"`
	ImageManifestDescriptor *imageDescriptor `json:"ImageManifestDescriptor"`
}

func main() {
	if err := run(); err != nil {
		fail(err)
	}
}

func run() error {
	var sourceRoot, platform, image, output, accountsFile string
	flag.StringVar(&sourceRoot, "source-root", "", "absolute repository root")
	flag.StringVar(&platform, "platform", "", "linux/amd64 or linux/arm64/v8")
	flag.StringVar(&image, "image", "", "local image reference to resolve")
	flag.StringVar(&accountsFile, "accounts-file", "", "absolute private canonical workload account allowlist")
	flag.StringVar(&output, "output", "", "absolute candidate manifest path outside the source tree")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	root, err := filepath.Abs(sourceRoot)
	if err != nil || !filepath.IsAbs(sourceRoot) || !filepath.IsAbs(output) || image == "" {
		return errors.New("absolute source/output and image are required")
	}
	accounts, err := desktopcandidate.LoadAccountAllowlist(accountsFile)
	if err != nil {
		return errors.New("candidate workload account allowlist is invalid")
	}
	relative, err := filepath.Rel(root, output)
	if err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return errors.New("candidate manifest must be outside the source tree")
	}
	for _, path := range []string{output, output + ".oci.tar"} {
		if _, statErr := os.Lstat(path); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("candidate output already exists or cannot be inspected")
		}
	}
	directoryInfo, err := os.Lstat(filepath.Dir(output))
	owner, owned := directoryInfoOwner(directoryInfo)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 ||
		directoryInfo.Mode().Perm()&0o022 != 0 || !owned || owner != uint32(os.Getuid()) {
		return errors.New("candidate output directory is not private and owner-controlled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	statusCommand := exec.CommandContext(ctx, "git", "status", "--porcelain", "--untracked-files=all")
	statusCommand.Dir = root
	status, err := statusCommand.Output()
	if err != nil || len(status) != 0 {
		return errors.New("Phase 6 candidate source tree must be clean and committed")
	}
	document, err := dockerOutput(ctx, "image", "inspect", image)
	if err != nil {
		return errors.New("inspect local candidate image")
	}
	var inspections []imageInspection
	if json.Unmarshal(document, &inspections) != nil || len(inspections) != 1 {
		return errors.New("invalid local candidate image inspection")
	}
	inspection := inspections[0]
	wantArchitecture, wantVariant := "amd64", ""
	if platform == "linux/arm64/v8" {
		wantArchitecture, wantVariant = "arm64", "v8"
	} else if platform != "linux/amd64" {
		return errors.New("unsupported candidate platform")
	}
	if inspection.OS != "linux" || inspection.Architecture != wantArchitecture || (inspection.Variant != "" && inspection.Variant != wantVariant) ||
		inspection.Descriptor == nil || inspection.Descriptor.Digest != inspection.ID || !strings.HasPrefix(inspection.ID, "sha256:") {
		return errors.New("candidate image platform or digest mismatch")
	}
	// Resolve the candidate by its immutable local store descriptor. No tag or
	// pull fallback is allowed after this point.
	storeDocument, err := dockerOutput(ctx, "image", "inspect", inspection.ID)
	var stores []imageInspection
	if err != nil || json.Unmarshal(storeDocument, &stores) != nil || len(stores) != 1 ||
		stores[0].ID != inspection.ID || stores[0].Descriptor == nil || *stores[0].Descriptor != *inspection.Descriptor {
		return errors.New("immutable local store descriptor changed during inspection")
	}
	name := fmt.Sprintf("sr-desktop-candidate-observe-%d", time.Now().UnixNano())
	containerID, err := dockerOutput(ctx, "create", "--pull=never", "--name", name, "--network", "none", inspection.ID)
	if err != nil {
		return errors.New("create exact stopped candidate observation container")
	}
	containerIDText := strings.TrimSpace(string(containerID))
	defer func() {
		if containerIDText == "" {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if _, cleanupErr := dockerOutput(cleanup, "rm", "-f", containerIDText); cleanupErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "exact candidate observation container cleanup failed: %v\n", cleanupErr)
		}
	}()
	containerDocument, err := dockerOutput(ctx, "inspect", containerIDText)
	if err != nil {
		return errors.New("inspect selected candidate runtime manifest")
	}
	var containers []containerInspection
	if json.Unmarshal(containerDocument, &containers) != nil || len(containers) != 1 || containers[0].ID != containerIDText ||
		containers[0].Image != inspection.ID || containers[0].ImageManifestDescriptor == nil {
		return errors.New("candidate runtime selected manifest is absent")
	}
	selected := containers[0].ImageManifestDescriptor
	kind := phase6security.ImageIdentityOCIManifest
	if inspection.Descriptor.MediaType == "application/vnd.oci.image.index.v1+json" ||
		inspection.Descriptor.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		kind = phase6security.ImageIdentityOCIIndex
	}
	directory := filepath.Dir(output)
	temporary, err := os.CreateTemp(directory, ".desktop-phase6-archive-*.tar")
	if err != nil {
		return errors.New("create private candidate archive")
	}
	temporaryPath := temporary.Name()
	if temporary.Close() != nil || os.Chmod(temporaryPath, 0o600) != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("secure private candidate archive")
	}
	defer os.Remove(temporaryPath)
	if outputBytes, saveErr := exec.CommandContext(ctx, "docker", "image", "save", "-o", temporaryPath, inspection.ID).CombinedOutput(); saveErr != nil {
		return fmt.Errorf("save candidate OCI archive: %v: %.512s", saveErr, outputBytes)
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return err
	}
	selectedDigest := selected.Digest
	documents, err := phase6security.ReadOCIArchiveDocuments(temporaryPath, kind, inspection.ID, selectedDigest, "")
	if err != nil {
		return err
	}
	var selectedManifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if json.Unmarshal(documents.Manifest, &selectedManifest) != nil {
		return errors.New("invalid selected candidate manifest")
	}
	configDigest := selectedManifest.Config.Digest
	documents, err = phase6security.ReadOCIArchiveDocuments(temporaryPath, kind, inspection.ID, selectedDigest, configDigest)
	if err != nil || phase6security.VerifyOCIArchiveLayers(temporaryPath, documents.Manifest, documents.Config) != nil {
		return errors.New("candidate archive blob/layer chain invalid")
	}
	selectedArgument := ""
	if kind == phase6security.ImageIdentityOCIIndex {
		selectedArgument = selectedDigest
	}
	proof, err := phase6security.VerifyImageDescriptorDocuments("local", kind, inspection.ID, inspection.ID, platform, selectedArgument, configDigest, documents)
	if err != nil {
		return errors.New("candidate descriptor chain invalid")
	}
	if _, err := phase6security.ObserveDockerRuntimeImage(containerDocument, storeDocument, "local", kind,
		inspection.ID, inspection.ID, platform, selectedArgument, configDigest, documents); err != nil {
		return errors.New("candidate Docker runtime selection differs from archive")
	}
	archive, err := os.Open(temporaryPath)
	if err != nil {
		return err
	}
	archiveHash := sha256.New()
	archiveSize, hashErr := io.Copy(archiveHash, archive)
	_ = archive.Close()
	if hashErr != nil {
		return hashErr
	}
	candidate, err := desktopcandidate.NewCurrent(root, platform, desktopcandidate.CurrentIdentity{
		Accounts:     accounts,
		Kind:         kind,
		Store:        phase6security.ImageDescriptor{MediaType: inspection.Descriptor.MediaType, Digest: inspection.ID, Size: inspection.Descriptor.Size},
		Selected:     phase6security.ImageDescriptor{MediaType: selected.MediaType, Digest: selected.Digest, Size: selected.Size},
		ConfigDigest: configDigest, DescriptorProofDigest: proof.ProofDigest,
		ArchiveDigest: "sha256:" + hex.EncodeToString(archiveHash.Sum(nil)), ArchiveSize: archiveSize,
	})
	if err != nil {
		return err
	}
	labels := inspection.Config.Labels
	if labels["io.github.shell-echo.sandbox-runtime.profile"] != candidate.ProfileID ||
		labels["io.github.shell-echo.sandbox-runtime.candidate-classification"] != candidate.Classification ||
		labels["io.github.shell-echo.sandbox-runtime.candidate-apk-lock-digest"] != candidate.APKLockDigest ||
		labels["org.opencontainers.image.revision"] != candidate.SourceRevision ||
		labels["org.opencontainers.image.base.digest"] != candidate.BaseImageDigest ||
		labels["io.github.shell-echo.sandbox-runtime.package-archive-set-digest"] != candidate.PackageArchiveSetDigest ||
		labels["io.github.shell-echo.sandbox-runtime.installed-set-digest"] != candidate.InstalledSetDigest {
		return errors.New("candidate image labels do not match source/build authority")
	}
	if labels["io.github.shell-echo.sandbox-runtime.workload-account-digest"] != candidate.WorkloadAccountDigest {
		return errors.New("candidate image labels do not match source/build authority")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	if _, err := dockerOutput(cleanup, "rm", "-f", containerIDText); err != nil {
		return errors.New("exact candidate observation container cleanup failed")
	}
	if _, err := dockerOutput(cleanup, "inspect", containerIDText); err == nil {
		return errors.New("candidate observation container remained after cleanup")
	}
	containerIDText = ""
	archivePath := output + ".oci.tar"
	if err := os.Link(temporaryPath, archivePath); err != nil {
		return err
	}
	if err := candidate.VerifyArchive(archivePath); err != nil {
		_ = os.Remove(archivePath)
		return err
	}
	if err := desktopcandidate.Save(output, candidate); err != nil {
		_ = os.Remove(archivePath)
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "candidate=%s\nimage=%s\nmanifest=%s\n", candidate.Classification, candidate.ImageDigest, candidate.ManifestDigest)
	return nil
}

func dockerOutput(ctx context.Context, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", arguments...).Output()
}

func directoryInfoOwner(info os.FileInfo) (uint32, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(stat.Uid), true
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

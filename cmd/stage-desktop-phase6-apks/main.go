package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	image "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
)

func main() {
	var lockPath, output, cache string
	flag.StringVar(&lockPath, "lock", "", "absolute Phase 6 candidate APK lock")
	flag.StringVar(&output, "output", "", "absolute private build context")
	flag.StringVar(&cache, "cache", "", "optional absolute closed archive directory")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(lockPath) || !filepath.IsAbs(output) ||
		(cache != "" && !filepath.IsAbs(cache)) {
		fail(errors.New("absolute lock, output and optional cache are required"))
	}
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		fail(errors.New("private build context is required"))
	}
	lock, err := image.LoadAPKLock(lockPath)
	if err != nil {
		fail(err)
	}
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		fail(errors.New("read Phase 6 APK lock"))
	}
	lockDigest := sha256.Sum256(lockBytes)
	archiveDir := filepath.Join(output, "apks")
	if err := os.Mkdir(archiveDir, 0o700); err != nil {
		fail(errors.New("create private APK staging directory"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := lock.StageAPKDirectory(ctx, archiveDir, cache); err != nil {
		fail(err)
	}
	if err := lock.WriteAPKChecksums(filepath.Join(output, "SHA256SUMS")); err != nil {
		fail(err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "archive_set_digest=%s\ninstalled_set_digest=%s\nlock_digest=sha256:%x\nbase_image_digest=%s\n",
		lock.ArchiveDigest, lock.InstalledDigest, lockDigest, lock.BaseImageDigest)
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

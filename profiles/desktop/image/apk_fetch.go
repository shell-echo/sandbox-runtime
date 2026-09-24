package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StageAPKDirectory obtains only the exact lock entries. An explicit cache is
// verified in full and never silently replaced from the network. Otherwise
// each fixed HTTPS URL is fetched without redirects, proxies or mirrors.
func (l APKLock) StageAPKDirectory(ctx context.Context, destination, cache string) error {
	if ctx == nil || l.Validate() != nil || !filepath.IsAbs(destination) ||
		(cache != "" && !filepath.IsAbs(cache)) || validateEmptyAPKDestination(destination) != nil {
		return ErrInvalidAPKLock
	}
	if cache != "" && l.VerifyAPKDirectory(cache) != nil {
		return ErrInvalidAPKLock
	}
	client := &http.Client{Timeout: 30 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidAPKLock }}
	for _, item := range l.Packages {
		path := filepath.Join(destination, item.Filename())
		var err error
		if cache != "" {
			err = copyLockedAPK(path, filepath.Join(cache, item.Filename()), item)
		} else {
			err = fetchLockedAPK(ctx, client, item.URL(l), path, item)
		}
		if err != nil {
			return ErrInvalidAPKLock
		}
	}
	return l.VerifyAPKDirectory(destination)
}

func validateEmptyAPKDestination(destination string) error {
	info, err := os.Lstat(destination)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrInvalidAPKLock
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 0 {
		return ErrInvalidAPKLock
	}
	return nil
}

func copyLockedAPK(destination, source string, item LockedAPK) error {
	input, err := os.Open(source)
	if err != nil {
		return ErrInvalidAPKLock
	}
	defer input.Close()
	return writeLockedAPK(destination, input, item)
}

func fetchLockedAPK(ctx context.Context, client *http.Client, url, destination string, item LockedAPK) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ErrInvalidAPKLock
	}
	response, err := client.Do(request)
	if err != nil {
		return ErrInvalidAPKLock
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > item.Size {
		return ErrInvalidAPKLock
	}
	return writeLockedAPK(destination, response.Body, item)
}

func writeLockedAPK(destination string, source io.Reader, item LockedAPK) (result error) {
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrInvalidAPKLock
	}
	defer func() {
		if result != nil {
			_ = os.Remove(destination)
		}
	}()
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(source, item.Size+1))
	if copyErr != nil || count != item.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
		_ = output.Close()
		return ErrInvalidAPKLock
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return ErrInvalidAPKLock
	}
	if err := output.Close(); err != nil {
		return ErrInvalidAPKLock
	}
	return nil
}

// WriteAPKChecksums creates a docker-build-side second integrity check.
// The context contains no remote repository index or auto-resolution step.
func (l APKLock) WriteAPKChecksums(path string) error {
	if l.Validate() != nil || !filepath.IsAbs(path) || filepath.Base(path) != "SHA256SUMS" {
		return ErrInvalidAPKLock
	}
	var content strings.Builder
	for _, item := range l.Packages {
		_, _ = fmt.Fprintf(&content, "%s  %s\n", strings.TrimPrefix(item.SHA256, "sha256:"), item.Filename())
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrInvalidAPKLock
	}
	if _, err := io.WriteString(file, content.String()); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return ErrInvalidAPKLock
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return ErrInvalidAPKLock
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return ErrInvalidAPKLock
	}
	return nil
}

func (l APKLock) VerifyArchiveSetDigest(expected string) error {
	if l.Validate() != nil || expected != l.ArchiveSetDigest() {
		return errors.New("candidate APK archive set does not match lock")
	}
	return nil
}

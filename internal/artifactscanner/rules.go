package artifactscanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const (
	RuleSnapshotProtocol = "sandbox-runtime.clamav-rule-snapshot.v1"
	RuleMaxAge           = 72 * time.Hour
	ruleManifestMaxBytes = 16 << 10
	ruleFileMaxBytes     = 512 << 20
)

var ErrRulesUnavailable = errors.New("verified malware rules unavailable")

type RuleFile struct {
	Name      string `json:"name"`
	Version   uint64 `json:"version"`
	SizeBytes int64  `json:"size_bytes"`
	Digest    string `json:"digest"`
}

// RuleManifest is an exact Profile-pinned assertion about a complete immutable
// official-rule snapshot. The runtime verifies the manifest digest and actual
// bytes; separate operator evidence must prove that the trusted current-check,
// official ClamAV signature verification, and engine load actually occurred.
type RuleManifest struct {
	Protocol             string     `json:"protocol"`
	EngineImageDigest    string     `json:"engine_image_digest"`
	EngineConfigDigest   string     `json:"engine_config_digest"`
	TrustedCheckAt       time.Time  `json:"trusted_check_at"`
	CurrentReceiptDigest string     `json:"current_receipt_digest"`
	Files                []RuleFile `json:"files"`
}

type RuleVersionFloor struct {
	Main     uint64
	Daily    uint64
	Bytecode uint64
}

type RuleVerifierConfig struct {
	ManifestPath         string
	RulesDirectory       string
	ExpectedRuleSet      string
	ExpectedEngineImage  string
	ExpectedEngineConfig string
	VersionFloor         RuleVersionFloor
}

type RuleVerifier struct {
	config      RuleVerifierConfig
	mu          sync.Mutex
	lastNow     time.Time
	clockRolled bool
}

func NewRuleVerifier(config RuleVerifierConfig) (*RuleVerifier, error) {
	if !absoluteClean(config.ManifestPath) || !absoluteClean(config.RulesDirectory) ||
		config.ManifestPath == config.RulesDirectory ||
		strings.HasPrefix(config.ManifestPath, config.RulesDirectory+string(filepath.Separator)) ||
		!scanDigestPattern.MatchString(config.ExpectedRuleSet) ||
		!scanDigestPattern.MatchString(config.ExpectedEngineImage) ||
		!scanDigestPattern.MatchString(config.ExpectedEngineConfig) ||
		config.VersionFloor.Main == 0 || config.VersionFloor.Daily == 0 || config.VersionFloor.Bytecode == 0 {
		return nil, ErrRulesUnavailable
	}
	return &RuleVerifier{config: config}, nil
}

func (v *RuleVerifier) Verify(ctx context.Context, now time.Time) (string, error) {
	if ctx == nil {
		return "", context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if v == nil || !absoluteClean(v.config.ManifestPath) || !absoluteClean(v.config.RulesDirectory) {
		return "", ErrRulesUnavailable
	}
	v.mu.Lock()
	if now.Before(v.lastNow) {
		v.clockRolled = true
	}
	if v.clockRolled {
		v.mu.Unlock()
		return "", ErrRulesUnavailable
	}
	v.lastNow = now
	v.mu.Unlock()
	manifestBytes, err := secretfile.Read(v.config.ManifestPath, ruleManifestMaxBytes)
	if err != nil {
		return "", ErrRulesUnavailable
	}
	var manifest RuleManifest
	if json.Unmarshal(manifestBytes, &manifest) != nil {
		return "", ErrRulesUnavailable
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(manifestBytes, canonical) ||
		manifest.Protocol != RuleSnapshotProtocol ||
		manifest.EngineImageDigest != v.config.ExpectedEngineImage ||
		manifest.EngineConfigDigest != v.config.ExpectedEngineConfig ||
		!scanDigestPattern.MatchString(manifest.CurrentReceiptDigest) ||
		manifest.TrustedCheckAt.IsZero() || manifest.TrustedCheckAt.After(now) ||
		now.Sub(manifest.TrustedCheckAt) > RuleMaxAge ||
		!validRuleFiles(manifest.Files, v.config.VersionFloor) {
		return "", ErrRulesUnavailable
	}
	if scanDigest(manifestBytes) != v.config.ExpectedRuleSet {
		return "", ErrRulesUnavailable
	}
	if err := verifyRuleDirectory(ctx, v.config.RulesDirectory, manifest.Files); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return v.config.ExpectedRuleSet, nil
}

func validRuleFiles(files []RuleFile, floor RuleVersionFloor) bool {
	if len(files) != 3 {
		return false
	}
	families := []string{"bytecode", "daily", "main"}
	minimum := []uint64{floor.Bytecode, floor.Daily, floor.Main}
	for index, file := range files {
		family := families[index]
		if (file.Name != family+".cvd" && file.Name != family+".cld") ||
			file.Version < minimum[index] || file.SizeBytes < 1 || file.SizeBytes > ruleFileMaxBytes ||
			!scanDigestPattern.MatchString(file.Digest) {
			return false
		}
	}
	return true
}

func verifyRuleDirectory(ctx context.Context, path string, files []RuleFile) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrRulesUnavailable
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return ErrRulesUnavailable
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return ErrRulesUnavailable
	}
	entries, readErr := directory.ReadDir(4)
	closeErr := directory.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) != len(files) {
		return ErrRulesUnavailable
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	want := make([]string, len(files))
	for index, file := range files {
		want[index] = file.Name
	}
	sort.Strings(want)
	for index := range names {
		if names[index] != want[index] {
			return ErrRulesUnavailable
		}
	}
	for _, expected := range files {
		before, err := root.Lstat(expected.Name)
		if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 || before.Size() != expected.SizeBytes {
			return ErrRulesUnavailable
		}
		file, err := root.Open(expected.Name)
		if err != nil {
			return ErrRulesUnavailable
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, opened) {
			_ = file.Close()
			return ErrRulesUnavailable
		}
		hash := sha256.New()
		buffer := make([]byte, 64<<10)
		var size int64
		for {
			if err := ctx.Err(); err != nil {
				_ = file.Close()
				return err
			}
			count, readErr := file.Read(buffer)
			if count > 0 {
				size += int64(count)
				if size > expected.SizeBytes {
					_ = file.Close()
					return ErrRulesUnavailable
				}
				_, _ = hash.Write(buffer[:count])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil || count == 0 {
				_ = file.Close()
				return ErrRulesUnavailable
			}
		}
		after, err := root.Lstat(expected.Name)
		closeErr := file.Close()
		if err != nil || closeErr != nil || !os.SameFile(before, after) || size != expected.SizeBytes ||
			"sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected.Digest {
			return ErrRulesUnavailable
		}
	}
	return nil
}

func absoluteClean(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

package artifactscanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
	document    []byte
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

// NewRuleVerifierFromDocument receives canonical bytes pinned by the Profile.
// Its exact versions are snapshot constraints, not cross-Profile anti-rollback.
// EngineImage is the separately locked ClamAV supply input, not the composite
// image containing this command. Source-to-image verification remains a gate.
func NewRuleVerifierFromDocument(document []byte, rulesDirectory, expectedRuleSet, expectedEngineImage, expectedEngineConfig string) (*RuleVerifier, error) {
	if len(document) < 1 || len(document) > ruleManifestMaxBytes || !absoluteClean(rulesDirectory) ||
		!scanDigestPattern.MatchString(expectedRuleSet) || scanDigest(document) != expectedRuleSet ||
		!scanDigestPattern.MatchString(expectedEngineImage) || !scanDigestPattern.MatchString(expectedEngineConfig) {
		return nil, ErrRulesUnavailable
	}
	var manifest RuleManifest
	if json.Unmarshal(document, &manifest) != nil {
		return nil, ErrRulesUnavailable
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, document) || manifest.Protocol != RuleSnapshotProtocol ||
		manifest.EngineImageDigest != expectedEngineImage || manifest.EngineConfigDigest != expectedEngineConfig || len(manifest.Files) != 3 {
		return nil, ErrRulesUnavailable
	}
	floor := RuleVersionFloor{Bytecode: manifest.Files[0].Version, Daily: manifest.Files[1].Version, Main: manifest.Files[2].Version}
	if floor.Main == 0 || floor.Daily == 0 || floor.Bytecode == 0 || !validRuleFiles(manifest.Files, floor) {
		return nil, ErrRulesUnavailable
	}
	return &RuleVerifier{config: RuleVerifierConfig{RulesDirectory: rulesDirectory, ExpectedRuleSet: expectedRuleSet, ExpectedEngineImage: expectedEngineImage,
		ExpectedEngineConfig: expectedEngineConfig, VersionFloor: floor}, document: bytes.Clone(document)}, nil
}

func (v *RuleVerifier) Verify(ctx context.Context, now time.Time) (string, error) {
	if ctx == nil {
		return "", context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if v == nil || (len(v.document) == 0 && !absoluteClean(v.config.ManifestPath)) || !absoluteClean(v.config.RulesDirectory) {
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
	manifestBytes := v.document
	if len(manifestBytes) == 0 {
		var err error
		manifestBytes, err = secretfile.Read(v.config.ManifestPath, ruleManifestMaxBytes)
		if err != nil {
			return "", ErrRulesUnavailable
		}
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

func verifyRuleDirectory(ctx context.Context, path string, files []RuleFile) (err error) {
	root, err := openRuleDirectory(path)
	if err != nil {
		return ErrRulesUnavailable
	}
	var opened []*ruleOriginalFile
	defer func() {
		for _, file := range opened {
			if file.file.Close() != nil {
				err = errors.Join(err, ErrRulesUnavailable)
			}
		}
		if root.file.Close() != nil {
			err = errors.Join(err, ErrRulesUnavailable)
		}
	}()
	if verifyRuleNames(root, files) != nil {
		return ErrRulesUnavailable
	}
	buffer := make([]byte, 64<<10)
	for _, expected := range files {
		file, err := root.open(expected.Name)
		if err != nil {
			return ErrRulesUnavailable
		}
		opened = append(opened, file)
		if file.size() != expected.SizeBytes {
			return ErrRulesUnavailable
		}
		hash := sha256.New()
		var size int64
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			count, readErr := file.file.Read(buffer)
			if count > 0 {
				size += int64(count)
				if size > expected.SizeBytes {
					return ErrRulesUnavailable
				}
				_, _ = hash.Write(buffer[:count])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil || count == 0 {
				return ErrRulesUnavailable
			}
		}
		if file.check() != nil || size != expected.SizeBytes || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected.Digest {
			return ErrRulesUnavailable
		}
	}
	// Keep all three descriptors until the entire snapshot has been hashed:
	// a rule checked earlier must not change while a later rule is read.
	if verifyRuleNames(root, files) != nil {
		return ErrRulesUnavailable
	}
	for _, file := range opened {
		if file.check() != nil {
			return ErrRulesUnavailable
		}
	}
	return root.check()
}

func verifyRuleNames(root *ruleDirectory, files []RuleFile) error {
	entries, err := root.entries()
	if err != nil || len(files) != 3 || len(entries) != len(files) {
		return ErrRulesUnavailable
	}
	names, want := make([]string, len(entries)), make([]string, len(files))
	for i, entry := range entries {
		names[i], want[i] = entry.Name(), files[i].Name
	}
	sort.Strings(names)
	sort.Strings(want)
	for i := range names {
		if names[i] != want[i] {
			return ErrRulesUnavailable
		}
	}
	return nil
}

func absoluteClean(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

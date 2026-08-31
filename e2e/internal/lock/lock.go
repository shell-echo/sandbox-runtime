package lock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	ProviderCommit   = "d58497e5359056858564b9ac663178958cf5a6d6"
	ContractNS       = "urn:shell-echo:sandbox-runtime:provider-v1"
	ContractRevision = "22a148e2898477790512d5bb742605654ff00ebf"
	ContractTree     = "1a967c9c6ce9646c8431f6ee48699ec9f406a589"
	SuiteCases       = 38
)

var (
	errDirtyHarness = errors.New("external caller harness has worktree changes")
	commitPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type providerLock struct {
	Source struct {
		Revision     string `json:"revision"`
		ContractTree string `json:"contract_tree"`
	} `json:"source"`
	Contract struct {
		Namespace string `json:"namespace"`
	} `json:"contract"`
	SandboxSuite struct {
		Path string `json:"path"`
	} `json:"sandbox_suite"`
}

type suite struct {
	Profiles []struct {
		Tests []string `json:"tests"`
	} `json:"profiles"`
}

// Verify rejects a checkout whose implementation or locked Contract differs
// from the evidence baseline. Documentation-only descendants are allowed so
// recording evidence does not invalidate the implementation lock.
func Verify(providerRoot string) error {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return fmt.Errorf("resolve Provider root: %w", err)
	}
	if dirty, err := git(root, "status", "--porcelain", "--untracked-files=no"); err != nil {
		return err
	} else if strings.TrimSpace(dirty) != "" {
		return errors.New("Provider checkout has tracked worktree changes")
	}
	if _, err := git(root, "merge-base", "--is-ancestor", ProviderCommit, "HEAD"); err != nil {
		return fmt.Errorf("Provider baseline %s is not an ancestor of HEAD: %w", ProviderCommit, err)
	}
	changed, err := git(root, "diff", "--name-only", ProviderCommit, "HEAD")
	if err != nil {
		return err
	}
	for _, path := range strings.Fields(changed) {
		if !providerDocumentationPath(path) {
			return fmt.Errorf("Provider implementation differs from %s at %s", ProviderCommit, path)
		}
	}
	actualTree, err := git(root, "rev-parse", "HEAD:contract")
	if err != nil {
		return err
	}
	if strings.TrimSpace(actualTree) != ContractTree {
		return fmt.Errorf("Provider Contract tree = %s, want %s", strings.TrimSpace(actualTree), ContractTree)
	}

	var locked providerLock
	if err := decodeFile(filepath.Join(root, "compatibility/sandbox-runtime/contract.lock.json"), &locked); err != nil {
		return err
	}
	if locked.Source.Revision != ContractRevision || locked.Source.ContractTree != ContractTree || locked.Contract.Namespace != ContractNS {
		return errors.New("Provider Contract lock identity differs from the E2E lock")
	}
	var cases suite
	if err := decodeFile(filepath.Join(root, locked.SandboxSuite.Path), &cases); err != nil {
		return err
	}
	count := 0
	for _, profile := range cases.Profiles {
		count += len(profile.Tests)
	}
	if count != SuiteCases {
		return fmt.Errorf("Provider Suite case count = %d, want %d", count, SuiteCases)
	}
	return nil
}

func providerDocumentationPath(path string) bool {
	return path == "README.md" || strings.HasPrefix(path, "docs/")
}

// HarnessRevision returns the exact independently versioned caller revision.
// Evidence runs refuse tracked or untracked source changes; ignored ephemeral
// evidence, runtime state, and secrets remain outside Git status.
func HarnessRevision(moduleRoot string) (string, error) {
	root, err := filepath.Abs(moduleRoot)
	if err != nil {
		return "", fmt.Errorf("resolve harness root: %w", err)
	}
	dirty, err := git(root, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(dirty) != "" {
		return "", errDirtyHarness
	}
	revision, err := git(root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", err
	}
	revision = strings.TrimSpace(revision)
	if !commitPattern.MatchString(revision) {
		return "", errors.New("external caller harness revision is invalid")
	}
	return revision, nil
}

func decodeFile(path string, target any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(content, target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func git(root string, args ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

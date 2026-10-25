//go:build !darwin && !linux

package artifactscanner

import "os"

const ruleCustodySupported = false

// A weaker filesystem identity is not a fallback for the private Unix scanner.
type ruleDirectory struct{ file *os.File }
type ruleOriginalFile struct{ file *os.File }

func openRuleDirectory(string) (*ruleDirectory, error) { return nil, ErrRulesUnavailable }
func (*ruleDirectory) check() error                    { return ErrRulesUnavailable }
func (*ruleDirectory) entries() ([]os.DirEntry, error) { return nil, ErrRulesUnavailable }
func (*ruleDirectory) open(string) (*ruleOriginalFile, error) {
	return nil, ErrRulesUnavailable
}
func (*ruleOriginalFile) size() int64  { return 0 }
func (*ruleOriginalFile) check() error { return ErrRulesUnavailable }

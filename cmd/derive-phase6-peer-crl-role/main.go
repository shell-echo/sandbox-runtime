// Command derive-phase6-peer-crl-role writes one minimal, private role CRL
// binding from an operator-pinned security profile and full source mapping.
// It never copies Vault locators into the role-readable output.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type options struct {
	profilePath   string
	profileDigest string
	sourcesPath   string
	sourcesDigest string
	principal     string
	postgresOwner string
	output        string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "derive Phase 6 peer CRL role binding failed")
		os.Exit(1)
	}
}

func run(arguments []string, result io.Writer) error {
	if result == nil {
		return errors.New("result writer is required")
	}
	flags := flag.NewFlagSet("derive-phase6-peer-crl-role", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var value options
	flags.StringVar(&value.profilePath, "profile", "", "private canonical Phase 6 security profile")
	flags.StringVar(&value.profileDigest, "profile-digest", "", "expected profile digest")
	flags.StringVar(&value.sourcesPath, "sources", "", "private canonical peer-CRL source mapping")
	flags.StringVar(&value.sourcesDigest, "sources-digest", "", "expected full source-mapping digest")
	flags.StringVar(&value.principal, "principal-digest", "", "exact local principal digest")
	flags.StringVar(&value.postgresOwner, "postgres-owner", "", "optional exact PostgreSQL-purpose owner")
	flags.StringVar(&value.output, "output", "", "new private role-binding file")
	if flags.Parse(arguments) != nil || len(flags.Args()) != 0 || !safePath(value.profilePath) ||
		!safePath(value.sourcesPath) || !safePath(value.output) ||
		value.profilePath == value.sourcesPath || value.profilePath == value.output || value.sourcesPath == value.output ||
		value.profileDigest == "" || value.sourcesDigest == "" || value.principal == "" {
		return errors.New("exact private input paths, digests and output are required")
	}
	profile, err := phase6security.VerifyFile(value.profilePath)
	if err != nil || profile.ProfileDigest != value.profileDigest {
		return errors.New("security profile is unavailable or does not match digest")
	}
	sources, err := phase6security.VerifyPeerCRLSourcesFile(value.sourcesPath, profile)
	if err != nil || sources.Digest() != value.sourcesDigest {
		return errors.New("peer CRL source mapping is unavailable or does not match digest")
	}
	var role phase6security.PeerCRLRoleDocument
	if value.postgresOwner == "" {
		role, err = phase6security.DerivePeerCRLRoleDocument(profile, sources, value.principal)
	} else {
		role, err = phase6security.DerivePostgresPeerCRLRoleDocument(profile, sources, value.postgresOwner)
	}
	if err != nil || role.ValidateForPrincipal(profile, value.sourcesDigest, value.principal) != nil {
		return errors.New("principal has no complete peer CRL role binding")
	}
	document, err := json.Marshal(role)
	if err != nil {
		return errors.New("encode peer CRL role binding")
	}
	defer clear(document)
	parent, err := os.Lstat(filepath.Dir(value.output))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 {
		return errors.New("peer CRL role output directory is not private")
	}
	file, err := os.OpenFile(value.output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create new peer CRL role binding")
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(value.output)
		}
	}()
	if _, err := file.Write(document); err != nil {
		return errors.New("write peer CRL role binding")
	}
	if file.Sync() != nil || file.Close() != nil {
		return errors.New("sync peer CRL role binding")
	}
	complete = true
	_, err = fmt.Fprintf(result, "peer_crl_role_digest=%s\npeer_crl_source_mapping_digest=%s\n", role.Digest(), value.sourcesDigest)
	return err
}

func safePath(path string) bool {
	return path != "" && strings.TrimSpace(path) == path && !strings.ContainsAny(path, "\x00\r\n") &&
		filepath.IsAbs(path) && filepath.Clean(path) == path
}

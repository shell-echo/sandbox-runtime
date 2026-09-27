package desktopcandidate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const (
	AccountAllowlistSchema = "sandbox.runtime/desktop-phase6-workload-accounts/v1"
	MaxWorkloadAccounts    = 1000
	maxAccountBytes        = 64 << 10
)

var ErrInvalidAccounts = errors.New("invalid Desktop Phase 6 workload account allowlist")

// WorkloadAccount is an image-supported identity, never an allocation grant.
// A Provider must separately authorize and reserve the exact profile slot.
type WorkloadAccount struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type AccountAllowlist struct {
	Schema   string            `json:"schema"`
	Accounts []WorkloadAccount `json:"accounts"`
}

func (a AccountAllowlist) Validate() error {
	if a.Schema != AccountAllowlistSchema || len(a.Accounts) < 1 || len(a.Accounts) > MaxWorkloadAccounts {
		return ErrInvalidAccounts
	}
	var previousUID uint32
	seenGIDs := make(map[uint32]struct{}, len(a.Accounts))
	for _, account := range a.Accounts {
		if account.UID < 10000 || account.UID > 60000 || account.GID < 10000 || account.GID > 60000 ||
			account.UID <= previousUID {
			return ErrInvalidAccounts
		}
		if _, duplicate := seenGIDs[account.GID]; duplicate {
			return ErrInvalidAccounts
		}
		seenGIDs[account.GID] = struct{}{}
		previousUID = account.UID
	}
	return nil
}

// Digest binds the canonical allowlist bytes before the image is built. The
// eventual OCI image digest is not part of this input, avoiding a digest loop.
func (a AccountAllowlist) Digest() (string, error) {
	if a.Validate() != nil {
		return "", ErrInvalidAccounts
	}
	encoded, err := json.Marshal(a)
	if err != nil {
		return "", ErrInvalidAccounts
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/desktop-workload-accounts/v1\x00"), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (a AccountAllowlist) Supports(uid, gid uint32) bool {
	if a.Validate() != nil {
		return false
	}
	for _, account := range a.Accounts {
		if account.UID == uid {
			return account.GID == gid
		}
	}
	return false
}

// SupportsSlots checks image capability against every authorized Desktop
// workload identity. Extra image-supported accounts do not become slot grants.
func (a AccountAllowlist) SupportsSlots(slots []phase6security.SandboxIdentitySlot) bool {
	if a.Validate() != nil || len(slots) == 0 {
		return false
	}
	for _, slot := range slots {
		if slot.Template != "desktop-sandbox-runtime" || !a.Supports(slot.WorkloadUID, slot.WorkloadGID) {
			return false
		}
	}
	return true
}

// NSSFragments produces deterministic, non-login passwd/group additions for
// an immutable image. The build must append these to its base files and must
// not grant supplementary groups or write them at container start.
func (a AccountAllowlist) NSSFragments() ([]byte, []byte, error) {
	if a.Validate() != nil {
		return nil, nil, ErrInvalidAccounts
	}
	var passwd, group bytes.Buffer
	for _, account := range a.Accounts {
		fmt.Fprintf(&passwd, "desktop-slot-%d:x:%d:%d::/tmp/desktop-home:/sbin/nologin\n", account.UID, account.UID, account.GID)
		fmt.Fprintf(&group, "desktop-slot-%d:x:%d:\n", account.GID, account.GID)
	}
	return passwd.Bytes(), group.Bytes(), nil
}

// LoadAccountAllowlist only accepts a private, canonical file controlled by
// the invoking build operator. The same exact bytes can be copied into the
// Docker build context and hashed into candidate evidence.
func LoadAccountAllowlist(path string) (AccountAllowlist, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return AccountAllowlist{}, ErrInvalidAccounts
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() < 1 || info.Size() > maxAccountBytes {
		return AccountAllowlist{}, ErrInvalidAccounts
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return AccountAllowlist{}, ErrInvalidAccounts
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return AccountAllowlist{}, ErrInvalidAccounts
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return AccountAllowlist{}, ErrInvalidAccounts
	}
	document, err := io.ReadAll(io.LimitReader(file, maxAccountBytes+1))
	if err != nil || len(document) > maxAccountBytes {
		return AccountAllowlist{}, ErrInvalidAccounts
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var allowlist AccountAllowlist
	if decoder.Decode(&allowlist) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || allowlist.Validate() != nil {
		return AccountAllowlist{}, ErrInvalidAccounts
	}
	canonical, err := json.Marshal(allowlist)
	if err != nil || !bytes.Equal(canonical, document) {
		return AccountAllowlist{}, ErrInvalidAccounts
	}
	return allowlist, nil
}

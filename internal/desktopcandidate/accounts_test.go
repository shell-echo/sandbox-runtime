package desktopcandidate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func validAccounts() AccountAllowlist {
	return AccountAllowlist{Schema: AccountAllowlistSchema, Accounts: []WorkloadAccount{{UID: 20000, GID: 30000}, {UID: 20001, GID: 30001}}}
}

func TestAccountAllowlistClosedFiniteIdentity(t *testing.T) {
	allowlist := validAccounts()
	if err := allowlist.Validate(); err != nil {
		t.Fatal(err)
	}
	digest, err := allowlist.Digest()
	if err != nil || !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		t.Fatalf("digest = %q, %v", digest, err)
	}
	if !allowlist.Supports(20000, 30000) || allowlist.Supports(20000, 30001) || allowlist.Supports(20002, 30002) {
		t.Fatal("image identity support mismatch")
	}
	passwd, group, err := allowlist.NSSFragments()
	if err != nil || string(passwd) != "desktop-slot-20000:x:20000:30000::/tmp/desktop-home:/sbin/nologin\n"+
		"desktop-slot-20001:x:20001:30001::/tmp/desktop-home:/sbin/nologin\n" ||
		string(group) != "desktop-slot-30000:x:30000:\n"+"desktop-slot-30001:x:30001:\n" {
		t.Fatalf("non-deterministic or privileged NSS fragments: %q %q %v", passwd, group, err)
	}
	slots := []phase6security.SandboxIdentitySlot{{Template: "desktop-sandbox-runtime", WorkloadUID: 20000, WorkloadGID: 30000}}
	if !allowlist.SupportsSlots(slots) {
		t.Fatal("assigned Desktop identity unsupported")
	}
	slots[0].WorkloadGID = 30001
	if allowlist.SupportsSlots(slots) {
		t.Fatal("UID-only match authorized a mismatched GID")
	}
	slots[0].Template = "browser-sandbox-runtime"
	if allowlist.SupportsSlots(slots) {
		t.Fatal("Desktop image accepted Browser slot")
	}
	for name, mutate := range map[string]func(*AccountAllowlist){
		"missing":       func(a *AccountAllowlist) { a.Accounts = nil },
		"schema":        func(a *AccountAllowlist) { a.Schema = "other" },
		"root":          func(a *AccountAllowlist) { a.Accounts[0].UID = 0 },
		"too high":      func(a *AccountAllowlist) { a.Accounts[0].GID = 60001 },
		"order":         func(a *AccountAllowlist) { slices.Reverse(a.Accounts) },
		"duplicate UID": func(a *AccountAllowlist) { a.Accounts[1].UID = a.Accounts[0].UID },
		"duplicate GID": func(a *AccountAllowlist) { a.Accounts[1].GID = a.Accounts[0].GID },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validAccounts()
			mutate(&candidate)
			if !errors.Is(candidate.Validate(), ErrInvalidAccounts) {
				t.Fatal("invalid identity list accepted")
			}
		})
	}
	large := AccountAllowlist{Schema: AccountAllowlistSchema}
	for index := range MaxWorkloadAccounts {
		large.Accounts = append(large.Accounts, WorkloadAccount{UID: uint32(10000 + index), GID: uint32(30000 + index)})
	}
	if large.Validate() != nil {
		t.Fatal("1000 finite accounts rejected")
	}
	large.Accounts = append(large.Accounts, WorkloadAccount{UID: 11000, GID: 31000})
	if large.Validate() == nil {
		t.Fatal("1001 accounts accepted")
	}
}

func TestLoadAccountAllowlistRejectsUnsafeOrNoncanonicalFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "accounts.json")
	canonical, err := json.Marshal(validAccounts())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAccountAllowlist(path)
	if err != nil || !loaded.Supports(20001, 30001) {
		t.Fatalf("canonical allowlist = %+v, %v", loaded, err)
	}
	for name, document := range map[string][]byte{
		"newline":   append(slices.Clone(canonical), '\n'),
		"unknown":   []byte(`{"schema":"` + AccountAllowlistSchema + `","accounts":[{"uid":20000,"gid":30000,"extra":1}]}`),
		"duplicate": []byte(`{"schema":"` + AccountAllowlistSchema + `","schema":"` + AccountAllowlistSchema + `","accounts":[{"uid":20000,"gid":30000}]}`),
		"extra":     []byte(`{"schema":"` + AccountAllowlistSchema + `","accounts":[{"uid":20000,"gid":30000}]}{}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, document, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadAccountAllowlist(path); !errors.Is(err, ErrInvalidAccounts) {
				t.Fatalf("unsafe document = %v", err)
			}
		})
	}
	if err := os.WriteFile(path, canonical, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccountAllowlist(path); !errors.Is(err, ErrInvalidAccounts) {
		t.Fatalf("public allowlist = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "accounts-link.json")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccountAllowlist(alias); !errors.Is(err, ErrInvalidAccounts) {
		t.Fatalf("symlink allowlist = %v", err)
	}
}

//go:build darwin || linux

package evidencefiles

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestReadSortsEntriesAndExcludesWithoutBypassingBounds(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "z.json"), `{"z":1}`)
	writeFile(t, filepath.Join(root, "a.json"), `{"a":1}`)
	writeFile(t, filepath.Join(root, "report.json"), "report")

	inventory, err := Read(root, []string{"report.json"}, Options{MaxFiles: 3, MaxFileBytes: 100, MaxTotalBytes: 100})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if inventory.FileCount != 3 || inventory.TotalBytes != int64(len(`{"z":1}`)+len(`{"a":1}`)+len("report")) {
		t.Fatalf("inventory totals = (%d, %d)", inventory.FileCount, inventory.TotalBytes)
	}
	if len(inventory.Entries) != 2 {
		t.Fatalf("entries count = %d, want 2", len(inventory.Entries))
	}
	if got := inventory.Entries[0].Path; got != "a.json" {
		t.Fatalf("first path = %q, want a.json", got)
	}
	if got := inventory.Entries[1].Path; got != "z.json" {
		t.Fatalf("second path = %q, want z.json", got)
	}
	if inventory.Digest == "" || !strings.HasPrefix(inventory.Digest, "sha256:") {
		t.Fatalf("inventory digest = %q", inventory.Digest)
	}
	computed, err := DigestEntries(inventory.Entries)
	if err != nil || computed != inventory.Digest {
		t.Fatalf("DigestEntries() = (%q, %v), inventory digest %q", computed, err, inventory.Digest)
	}
}

func TestReadCountsExcludedFilesAgainstLimits(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "report.json"), "12345")
	if _, err := Read(root, []string{"report.json"}, Options{MaxFiles: 1, MaxFileBytes: 100, MaxTotalBytes: 4}); err == nil || !strings.Contains(err.Error(), "total bytes") {
		t.Fatalf("Read() error = %v, want total-byte overflow", err)
	}
	if _, err := Read(root, []string{"report.json"}, Options{MaxFiles: 0, MaxFileBytes: 100, MaxTotalBytes: 100}); err == nil || !strings.Contains(err.Error(), "MaxFiles") {
		t.Fatalf("Read() error = %v, want invalid MaxFiles", err)
	}
}

func TestReadRejectsPerFileAndFileCountOverflow(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "large.bin"), "12345")
	if _, err := Read(root, nil, Options{MaxFiles: 2, MaxFileBytes: 4, MaxTotalBytes: 100}); err == nil || !strings.Contains(err.Error(), "large.bin") {
		t.Fatalf("Read() error = %v, want per-file overflow", err)
	}
	writeFile(t, filepath.Join(root, "second.bin"), "1")
	if _, err := Read(root, nil, Options{MaxFiles: 1, MaxFileBytes: 100, MaxTotalBytes: 100}); err == nil || !strings.Contains(err.Error(), "regular files") {
		t.Fatalf("Read() error = %v, want file-count overflow", err)
	}
}

func TestReadRejectsDirectoriesIncludingEmpty(t *testing.T) {
	for _, test := range []struct {
		name     string
		populate bool
	}{
		{name: "empty"},
		{name: "non-empty", populate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "nested")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.populate {
				writeFile(t, filepath.Join(directory, "payload.json"), `{"ok":true}`)
			}
			if _, err := Read(root, nil, DefaultOptions()); err == nil || !strings.Contains(err.Error(), "must not be a directory") {
				t.Fatalf("Read() error = %v, want directory rejection", err)
			}
		})
	}
}

func TestReadRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	writeFile(t, target, "target")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Read(root, nil, DefaultOptions()); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Read() error = %v, want symlink rejection", err)
	}
	if _, err := Read(link, nil, DefaultOptions()); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("Read(symlink root) error = %v, want root rejection", err)
	}
}

func TestReadRejectsInvalidExclusionsAndRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "file"), "x")
	for _, exclusion := range []string{"", ".", "../file", "/file", "a\\b", "file"} {
		exclusions := []string{exclusion}
		if exclusion == "file" {
			exclusions = []string{"file", "file"}
		}
		if _, err := Read(root, exclusions, DefaultOptions()); err == nil {
			t.Errorf("Read(exclusions=%q) accepted invalid exclusion", exclusions)
		}
	}
	if _, err := Read(filepath.Join(root, "missing"), nil, DefaultOptions()); err == nil {
		t.Fatal("Read(missing root) accepted missing directory")
	}
}

func TestOpenRootReadsThroughHeldDirectoryDescriptor(t *testing.T) {
	rootPath := t.TempDir()
	writeFile(t, filepath.Join(rootPath, "payload.json"), `{"ok":true}`)
	writeFile(t, filepath.Join(rootPath, "report.json"), "report")
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	contents, err := root.ReadFile("payload.json", 100)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := string(contents), `{"ok":true}`; got != want {
		t.Fatalf("ReadFile() = %q, want %q", got, want)
	}
	inventory, err := root.Read([]string{"report.json"}, Options{MaxFiles: 2, MaxFileBytes: 100, MaxTotalBytes: 100})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if inventory.FileCount != 2 || len(inventory.Entries) != 1 || inventory.Entries[0].Path != "payload.json" {
		t.Fatalf("Read() inventory = %#v", inventory)
	}
}

func TestRootReadFileAndPublishRejectNestedPaths(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	if _, err := root.ReadFile("nested/payload.json", 100); err == nil || !strings.Contains(err.Error(), "directly at the evidence root") {
		t.Fatalf("ReadFile() error = %v, want nested-path rejection", err)
	}
	if _, err := root.Publish("nested/receipt.json", []byte("receipt"), 100); err == nil || !strings.Contains(err.Error(), "directly at the evidence root") {
		t.Fatalf("Publish() error = %v, want nested-path rejection", err)
	}
}

func TestPublishCreatesMode0600AndReadsBackThroughHeldRoot(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	publication, err := root.Publish("receipt.json", []byte("receipt\n"), 100)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if publication.Path() != "receipt.json" || publication.Size() != int64(len("receipt\n")) {
		t.Fatalf("publication = (%q, %d)", publication.Path(), publication.Size())
	}
	info, err := os.Lstat(filepath.Join(rootPath, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("receipt mode = %o, want 600", got)
	}
	contents, err := publication.Read(100)
	if err != nil {
		t.Fatalf("Publication.Read() error = %v", err)
	}
	if got, want := string(contents), "receipt\n"; got != want {
		t.Fatalf("Publication.Read() = %q, want %q", got, want)
	}
	if err := publication.Remove(); err != nil {
		t.Fatalf("Publication.Remove() error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, "receipt.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt remains after Remove(): %v", err)
	}
}

func TestPublishRejectsReplacedRootWithoutWritingReplacement(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "evidence")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	originalPath := filepath.Join(parent, "original-evidence")
	if err := os.Rename(rootPath, originalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := root.Publish("receipt.json", []byte("receipt"), 100); err == nil || !strings.Contains(err.Error(), "root path was replaced") {
		t.Fatalf("Publish() error = %v, want root replacement rejection", err)
	}
	for _, path := range []string{filepath.Join(rootPath, "receipt.json"), filepath.Join(originalPath, "receipt.json")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Publish() wrote %q after root replacement: %v", path, err)
		}
	}
}

func TestPublishNeverOverwritesExistingReceipt(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	receiptPath := filepath.Join(rootPath, "receipt.json")
	writeFile(t, receiptPath, "existing")

	if _, err := root.Publish("receipt.json", []byte("replacement"), 100); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Publish() error = %v, want existing-file rejection", err)
	}
	contents, err := os.ReadFile(receiptPath)
	if err != nil || string(contents) != "existing" {
		t.Fatalf("existing receipt = %q, %v", contents, err)
	}
}

func TestPublishNeverFollowsExistingReceiptSymlink(t *testing.T) {
	rootPath := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	writeFile(t, outside, "outside")
	if err := os.Symlink(outside, filepath.Join(rootPath, "receipt.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	if _, err := root.Publish("receipt.json", []byte("replacement"), 100); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Publish() error = %v, want symlink rejection", err)
	}
	contents, err := os.ReadFile(outside)
	if err != nil || string(contents) != "outside" {
		t.Fatalf("symlink target = %q, %v", contents, err)
	}
}

func TestPublicationRejectsReplacedFinalEntryWithoutRemovingIt(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	publication, err := root.Publish("receipt.json", []byte("receipt"), 100)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	receiptPath := filepath.Join(rootPath, "receipt.json")
	if err := os.Remove(receiptPath); err != nil {
		t.Fatal(err)
	}
	writeFile(t, receiptPath, "attacker replacement")

	if _, err := publication.Read(100); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("Publication.Read() error = %v, want identity rejection", err)
	}
	if err := publication.Remove(); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("Publication.Remove() error = %v, want identity rejection", err)
	}
	contents, err := os.ReadFile(receiptPath)
	if err != nil || string(contents) != "attacker replacement" {
		t.Fatalf("replacement receipt = %q, %v", contents, err)
	}
}

func TestCommitRejectsAndPreservesSuspiciousStagingHardlink(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	publication, err := root.Publish(".receipt.pending-test", []byte("receipt"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(rootPath, publication.Path()), filepath.Join(rootPath, "receipt.json")); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}
	if err := publication.Commit("receipt.json"); err == nil || !strings.Contains(err.Error(), "clean up staged evidence file") {
		t.Fatalf("Commit() error = %v, want rejection without unlinking suspicious entries", err)
	}
	for _, name := range []string{publication.Path(), "receipt.json"} {
		if _, statErr := os.Lstat(filepath.Join(rootPath, name)); statErr != nil {
			t.Fatalf("Commit() removed suspicious hardlink %q: %v", name, statErr)
		}
	}
}

func TestCommitPublishesStagedReceipt(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	publication, err := root.Publish(".receipt.pending-success", []byte("receipt\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit("receipt.json"); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if publication.Path() != "receipt.json" {
		t.Fatalf("committed publication path = %q", publication.Path())
	}
	if _, err := os.Lstat(filepath.Join(rootPath, ".receipt.pending-success")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging entry remains after Commit(): %v", err)
	}
	contents, err := publication.Read(100)
	if err != nil || string(contents) != "receipt\n" {
		t.Fatalf("committed receipt = %q, %v", contents, err)
	}
	info, err := os.Lstat(filepath.Join(rootPath, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("committed receipt mode = %v", info.Mode())
	}
}

func TestCommitRejectsDestinationCreatedAfterStaging(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	publication, err := root.Publish(".receipt.pending-destination-race", []byte("candidate"), 100)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(rootPath, "receipt.json"), "existing")
	if err := publication.Commit("receipt.json"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Commit() destination race error = %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(rootPath, "receipt.json"))
	if err != nil || string(contents) != "existing" {
		t.Fatalf("existing destination = %q, %v", contents, err)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, ".receipt.pending-destination-race")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging entry remains after destination race: %v", err)
	}
}

func TestConcurrentCommitsPublishExactlyOneReceipt(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	first, err := root.Publish(".receipt.pending-first", []byte("first"), 100)
	if err != nil {
		t.Fatal(err)
	}
	second, err := root.Publish(".receipt.pending-second", []byte("second"), 100)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errorsByCandidate := make([]error, 2)
	var wait sync.WaitGroup
	for index, publication := range []*Publication{first, second} {
		wait.Add(1)
		go func(index int, publication *Publication) {
			defer wait.Done()
			<-start
			errorsByCandidate[index] = publication.Commit("receipt.json")
		}(index, publication)
	}
	close(start)
	wait.Wait()

	successes := 0
	for _, err := range errorsByCandidate {
		if err == nil {
			successes++
			continue
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("losing Commit() error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful commits = %d, errors = %v", successes, errorsByCandidate)
	}
	contents, err := os.ReadFile(filepath.Join(rootPath, "receipt.json"))
	if err != nil || (string(contents) != "first" && string(contents) != "second") {
		t.Fatalf("committed receipt = %q, %v", contents, err)
	}
	for _, name := range []string{".receipt.pending-first", ".receipt.pending-second"} {
		if _, err := os.Lstat(filepath.Join(rootPath, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging entry %q remains after concurrent commits: %v", name, err)
		}
	}
}

func TestCommitRejectsChangedStagingContentsAndPreservesEntry(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	const staging = ".receipt.pending-content-race"
	publication, err := root.Publish(staging, []byte("original"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, staging), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit("receipt.json"); err == nil || !strings.Contains(err.Error(), "contents changed") || !strings.Contains(err.Error(), "clean up staged evidence file") {
		t.Fatalf("Commit() changed-content error = %v", err)
	}
	contents, readErr := os.ReadFile(filepath.Join(rootPath, staging))
	if readErr != nil || string(contents) != "tampered" {
		t.Fatalf("Commit() altered suspicious staging entry: %q, %v", contents, readErr)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, "receipt.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Commit() published receipt after changed-content rejection: %v", err)
	}
}

func TestCommitRejectsReplacedRootAndCleansStagingThroughHeldRoot(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "evidence")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	const staging = ".receipt.pending-root-race"
	publication, err := root.Publish(staging, []byte("receipt"), 100)
	if err != nil {
		t.Fatal(err)
	}
	originalPath := filepath.Join(parent, "original-evidence")
	if err := os.Rename(rootPath, originalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit("receipt.json"); err == nil || !strings.Contains(err.Error(), "root path was replaced") {
		t.Fatalf("Commit() root replacement error = %v", err)
	}
	for _, path := range []string{filepath.Join(originalPath, staging), filepath.Join(originalPath, "receipt.json"), filepath.Join(rootPath, "receipt.json")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Commit() left %q after root replacement: %v", path, err)
		}
	}
}

func TestRootRejectsEvidenceHardlink(t *testing.T) {
	rootPath := t.TempDir()
	payloadPath := filepath.Join(rootPath, "payload.json")
	writeFile(t, payloadPath, `{"ok":true}`)
	outsideLink := filepath.Join(t.TempDir(), "payload-hardlink.json")
	if err := os.Link(payloadPath, outsideLink); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	if _, err := root.Read(nil, DefaultOptions()); err == nil || !strings.Contains(err.Error(), "singly linked") {
		t.Fatalf("Read() error = %v, want hardlink rejection", err)
	}
}

func TestPublicationRejectsAddedHardlinkWithoutRemovingEitherName(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	publication, err := root.Publish("receipt.json", []byte("receipt"), 100)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	outsideLink := filepath.Join(t.TempDir(), "receipt-hardlink.json")
	if err := os.Link(filepath.Join(rootPath, "receipt.json"), outsideLink); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}

	if _, err := publication.Read(100); err == nil {
		t.Fatal("Publication.Read() accepted a multiply linked receipt")
	}
	if err := publication.Remove(); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("Publication.Remove() error = %v, want hardlink rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, "receipt.json")); err != nil {
		t.Fatalf("receipt removed despite hardlink: %v", err)
	}
	if _, err := os.Lstat(outsideLink); err != nil {
		t.Fatalf("outside hardlink removed: %v", err)
	}
	if err := os.Remove(outsideLink); err != nil {
		t.Fatal(err)
	}
	if err := publication.Remove(); err != nil {
		t.Fatalf("Publication.Remove() after hardlink removal error = %v", err)
	}
}

func TestRootRejectsSymlinkAndFilesystemRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "evidence-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := OpenRoot(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("OpenRoot(symlink) error = %v", err)
	}
	if _, err := OpenRoot(string(filepath.Separator)); err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("OpenRoot(filesystem root) error = %v", err)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

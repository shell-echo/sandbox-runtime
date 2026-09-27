package phase6rolecandidate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordRejectsInvalidInputBeforeDockerOrSource(t *testing.T) {
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	base := RecordInput{SourceRoot: private, Deployment: "product-runtime", Platform: "linux/arm64/v8",
		ImageID: "sha256:" + strings.Repeat("a", 64), OutputPath: filepath.Join(private, "candidate.json")}
	for name, change := range map[string]func(*RecordInput){
		"inside source":   func(input *RecordInput) { input.OutputPath = filepath.Join(private, "candidate.json") },
		"tag":             func(input *RecordInput) { input.ImageID = "local:mutable" },
		"relative root":   func(input *RecordInput) { input.SourceRoot = "." },
		"relative output": func(input *RecordInput) { input.OutputPath = "candidate.json" },
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			change(&input)
			if _, err := Record(context.Background(), input); err == nil {
				t.Fatal("invalid candidate recorder input admitted")
			}
		})
	}
	if isOutsideSource(private, base.OutputPath) {
		t.Fatal("source-relative output considered private external artifact")
	}
	if !isOutsideSource(private, filepath.Join(filepath.Dir(private), "outside.json")) {
		t.Fatal("external sibling output rejected")
	}
}

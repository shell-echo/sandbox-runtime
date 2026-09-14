package jsonschemaecma

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type locatedPattern struct {
	location string
	value    string
}

func TestNewCompilerUsesECMAScript(t *testing.T) {
	compiler := NewCompiler()
	if err := compiler.AddResource("urn:test:ecmascript", map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "string",
		"pattern": "^\\u{1F600}$",
	}); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:test:ecmascript")
	if err != nil {
		t.Fatalf("compile Unicode ECMA-262 code point escape: %v", err)
	}
	if err := schema.Validate("😀"); err != nil {
		t.Fatalf("Unicode ECMA-262 code point escape did not match U+1F600: %v", err)
	}
	if err := schema.Validate("u{1F600}"); err == nil {
		t.Fatal("Unicode ECMA-262 code point escape matched literal source text")
	}
}

func TestQualificationSchemaPatternsCompileAsECMAScript(t *testing.T) {
	paths := []string{
		"qualification/external-caller-coding-shell-v1/profile.schema.json",
		"qualification/external-caller-coding-shell-v1/report.schema.json",
		"qualification/external-caller-coding-shell-v1/adapter-protocol.schema.json",
	}
	var patterns []locatedPattern
	for _, relative := range paths {
		document, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(document, &value); err != nil {
			t.Fatalf("decode %s: %v", relative, err)
		}
		collectPatterns(relative, value, &patterns)
	}
	// The report embeds the pinned transcript resource, adding its id and
	// digest patterns to the existing 56 occurrences.
	if len(patterns) != 58 {
		t.Fatalf("qualification pattern count = %d, want 58", len(patterns))
	}
	sort.Slice(patterns, func(left, right int) bool {
		return patterns[left].location < patterns[right].location
	})
	for _, pattern := range patterns {
		if strings.Contains(pattern.value, "[:") {
			t.Errorf("%s contains a non-portable POSIX character class: %q", pattern.location, pattern.value)
			continue
		}
		if _, err := compile(pattern.value); err != nil {
			t.Errorf("compile %s pattern %q as ECMA-262: %v", pattern.location, pattern.value, err)
		}
	}
}

func collectPatterns(location string, value any, patterns *[]locatedPattern) {
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			child := location + "/" + key
			if key == "pattern" {
				if pattern, ok := item.(string); ok {
					*patterns = append(*patterns, locatedPattern{location: child, value: pattern})
				}
			}
			if key == "patternProperties" {
				if properties, ok := item.(map[string]any); ok {
					for pattern := range properties {
						*patterns = append(*patterns, locatedPattern{
							location: fmt.Sprintf("%s/%s", child, pattern),
							value:    pattern,
						})
					}
				}
			}
			collectPatterns(child, item, patterns)
		}
	case []any:
		for index, item := range value {
			collectPatterns(fmt.Sprintf("%s/%d", location, index), item, patterns)
		}
	}
}

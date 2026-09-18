// Package productcontract verifies the repository-owned Product Contract
// content lock without making an implementation or availability claim.
package productcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/jsonschemaecma"
	"go.yaml.in/yaml/v3"
)

const (
	ContractRoot = "product-contract"
	LockPath     = ContractRoot + "/compatibility/contract.lock.json"
	ManifestPath = ContractRoot + "/compatibility/contract-manifest.json"

	maxDocumentBytes = 8 << 20
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type lockDocument struct {
	LockFormat        int            `json:"lock_format"`
	ContractNamespace string         `json:"contract_namespace"`
	ContractVersion   string         `json:"contract_version"`
	Maturity          string         `json:"maturity"`
	DigestAlgorithm   string         `json:"digest_algorithm"`
	TreeDigestProfile string         `json:"tree_digest_profile"`
	ManifestDigest    string         `json:"manifest_digest"`
	TreeDigest        string         `json:"tree_digest"`
	Resources         []lockResource `json:"resources"`
}

type lockResource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type manifestDocument struct {
	ContractNamespace string             `json:"contract_namespace"`
	ContractVersion   string             `json:"contract_version"`
	Maturity          string             `json:"maturity"`
	Resources         []manifestResource `json:"resources"`
}

type manifestResource struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type semanticDocument struct {
	ContractNamespace string         `json:"contract_namespace"`
	ContractVersion   string         `json:"contract_version"`
	Maturity          string         `json:"maturity"`
	Rules             []semanticRule `json:"rules"`
}

type semanticRule struct {
	ID       string   `json:"id"`
	Requires []string `json:"requires"`
	Forbids  []string `json:"forbids"`
}

type conformanceSuite struct {
	SuiteID       string            `json:"suite_id"`
	SuiteVersion  string            `json:"suite_version"`
	ExecutionMode string            `json:"execution_mode"`
	Cases         []conformanceCase `json:"cases"`
}

type conformanceCase struct {
	CaseID  string `json:"case_id"`
	Package string `json:"package"`
	Test    string `json:"test"`
}

// Report identifies the exact local Product Contract content that was verified.
type Report struct {
	Namespace        string
	Version          string
	Maturity         string
	ManifestDigest   string
	TreeDigest       string
	ResourceCount    int
	OperationCount   int
	ConformanceCases int
}

// Verify validates the closed content lock, every locked byte resource, and
// the structural integrity of its JSON Schema and OpenAPI documents.
func Verify(sourceRoot string) (Report, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return Report{}, fmt.Errorf("resolve source root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Report{}, fmt.Errorf("resolve source root links: %w", err)
	}
	lockData, err := readRegular(filepath.Join(root, filepath.FromSlash(LockPath)))
	if err != nil {
		return Report{}, fmt.Errorf("read Product Contract lock: %w", err)
	}
	var lock lockDocument
	if err := decodeStrictJSON(lockData, &lock); err != nil {
		return Report{}, fmt.Errorf("decode Product Contract lock: %w", err)
	}
	if err := validateLock(lock); err != nil {
		return Report{}, err
	}

	manifestData, err := readRegular(filepath.Join(root, filepath.FromSlash(ManifestPath)))
	if err != nil {
		return Report{}, fmt.Errorf("read Product Contract manifest: %w", err)
	}
	if got := prefixedDigest(manifestData); got != lock.ManifestDigest {
		return Report{}, fmt.Errorf("Product Contract manifest digest %s, want %s", got, lock.ManifestDigest)
	}
	var manifest manifestDocument
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		return Report{}, fmt.Errorf("decode Product Contract manifest: %w", err)
	}
	if manifest.ContractNamespace != lock.ContractNamespace || manifest.ContractVersion != lock.ContractVersion || manifest.Maturity != lock.Maturity {
		return Report{}, errors.New("Product Contract manifest identity does not match lock")
	}

	lockedByPath := make(map[string]lockResource, len(lock.Resources))
	var tree bytes.Buffer
	resources := append([]lockResource(nil), lock.Resources...)
	sort.Slice(resources, func(i, j int) bool { return resources[i].Path < resources[j].Path })
	resourceData := make(map[string][]byte, len(resources))
	for _, resource := range resources {
		if _, duplicate := lockedByPath[resource.Path]; duplicate {
			return Report{}, fmt.Errorf("duplicate locked Product Contract resource %q", resource.Path)
		}
		lockedByPath[resource.Path] = resource
		data, err := readContractResource(root, resource.Path)
		if err != nil {
			return Report{}, err
		}
		if got := rawDigest(data); got != resource.SHA256 {
			return Report{}, fmt.Errorf("Product Contract resource %s digest %s, want %s", resource.Path, got, resource.SHA256)
		}
		resourceData[resource.Path] = data
		fmt.Fprintf(&tree, "%s\tsha256:%s\n", resource.Path, resource.SHA256)
	}
	if got := prefixedDigest(tree.Bytes()); got != lock.TreeDigest {
		return Report{}, fmt.Errorf("Product Contract tree digest %s, want %s", got, lock.TreeDigest)
	}
	if err := validateManifest(manifest, lockedByPath); err != nil {
		return Report{}, err
	}

	operationCount, conformanceCases, err := validateDocuments(manifest, resourceData)
	if err != nil {
		return Report{}, err
	}
	return Report{
		Namespace: lock.ContractNamespace, Version: lock.ContractVersion, Maturity: lock.Maturity,
		ManifestDigest: lock.ManifestDigest, TreeDigest: lock.TreeDigest,
		ResourceCount: len(resources), OperationCount: operationCount, ConformanceCases: conformanceCases,
	}, nil
}

func validateLock(lock lockDocument) error {
	if lock.LockFormat != 1 || lock.ContractNamespace != "urn:shell-echo:sandbox-runtime:product-v1alpha1" ||
		lock.ContractVersion != "0.1.0" || lock.Maturity != "phase-1-design-authority" ||
		lock.DigestAlgorithm != "sha256" || lock.TreeDigestProfile != "sorted-path-tab-prefixed-sha256-newline-v1" {
		return errors.New("unexpected Product Contract lock identity or profile")
	}
	for name, digest := range map[string]string{"manifest": lock.ManifestDigest, "tree": lock.TreeDigest} {
		if !strings.HasPrefix(digest, "sha256:") || !digestPattern.MatchString(strings.TrimPrefix(digest, "sha256:")) {
			return fmt.Errorf("Product Contract %s digest is not a lowercase SHA-256 digest", name)
		}
	}
	if len(lock.Resources) == 0 {
		return errors.New("Product Contract lock has no resources")
	}
	for _, resource := range lock.Resources {
		if !validResourcePath(resource.Path) || !digestPattern.MatchString(resource.SHA256) {
			return fmt.Errorf("invalid locked Product Contract resource %q", resource.Path)
		}
	}
	return nil
}

func validateManifest(manifest manifestDocument, locked map[string]lockResource) error {
	if len(manifest.Resources) != len(locked) {
		return errors.New("Product Contract manifest and lock resource counts differ")
	}
	kinds := map[string]bool{
		"openapi": true, "json-schema": true, "semantic-rules": true, "specification": true,
		"fixture": true, "conformance-suite": true,
	}
	seenPaths := make(map[string]bool, len(manifest.Resources))
	seenIDs := make(map[string]bool, len(manifest.Resources))
	for _, resource := range manifest.Resources {
		if !validResourcePath(resource.Path) || !kinds[resource.Kind] || strings.TrimSpace(resource.ID) == "" {
			return fmt.Errorf("invalid Product Contract manifest resource %q", resource.Path)
		}
		if seenPaths[resource.Path] || seenIDs[resource.ID] {
			return fmt.Errorf("duplicate Product Contract manifest resource %q", resource.Path)
		}
		seenPaths[resource.Path], seenIDs[resource.ID] = true, true
		if _, ok := locked[resource.Path]; !ok {
			return fmt.Errorf("manifest resource %q is not locked", resource.Path)
		}
	}
	return nil
}

func validateDocuments(manifest manifestDocument, documents map[string][]byte) (int, int, error) {
	byPath := make(map[string]manifestResource, len(manifest.Resources))
	var openAPI manifestResource
	var schema manifestResource
	for _, resource := range manifest.Resources {
		byPath[resource.Path] = resource
		switch resource.Kind {
		case "openapi":
			if openAPI.Path != "" {
				return 0, 0, errors.New("Product Contract contains multiple OpenAPI resources")
			}
			openAPI = resource
		case "json-schema":
			if schema.Path != "" {
				return 0, 0, errors.New("Product Contract contains multiple JSON Schema resources")
			}
			schema = resource
		case "semantic-rules":
			var semantic semanticDocument
			if err := decodeStrictJSON(documents[resource.Path], &semantic); err != nil {
				return 0, 0, fmt.Errorf("decode semantic rules: %w", err)
			}
			if err := validateSemanticDocument(semantic, manifest); err != nil {
				return 0, 0, err
			}
		}
	}
	if openAPI.Path == "" || schema.Path == "" {
		return 0, 0, errors.New("Product Contract requires exactly one OpenAPI and JSON Schema resource")
	}

	var schemaDocument any
	if err := decodeStrictJSON(documents[schema.Path], &schemaDocument); err != nil {
		return 0, 0, fmt.Errorf("decode Product JSON Schema: %w", err)
	}
	schemaObject, ok := schemaDocument.(map[string]any)
	if !ok || schemaObject["$id"] != schema.ID {
		return 0, 0, errors.New("Product JSON Schema ID does not match manifest")
	}
	compiler := jsonschemaecma.NewCompiler()
	if err := compiler.AddResource(schema.ID, schemaDocument); err != nil {
		return 0, 0, fmt.Errorf("register Product JSON Schema: %w", err)
	}
	if _, err := compiler.Compile(schema.ID); err != nil {
		return 0, 0, fmt.Errorf("compile Product JSON Schema: %w", err)
	}
	fixtureDefinitions := map[string]string{
		"fixtures/create-workspace-request.json": "CreateWorkspaceRequest",
		"fixtures/product-error.json":            "ProductError",
		"fixtures/product-operation.json":        "ProductOperation",
		"fixtures/workspace.json":                "Workspace",
	}
	for fixturePath, definition := range fixtureDefinitions {
		resource, ok := byPath[fixturePath]
		if !ok || resource.Kind != "fixture" {
			return 0, 0, fmt.Errorf("required Product fixture %q is absent", fixturePath)
		}
		var value any
		if err := decodeStrictJSON(documents[fixturePath], &value); err != nil {
			return 0, 0, fmt.Errorf("decode Product fixture %s: %w", fixturePath, err)
		}
		compiled, err := compiler.Compile(schema.ID + "#/$defs/" + definition)
		if err != nil {
			return 0, 0, fmt.Errorf("compile Product fixture definition %s: %w", definition, err)
		}
		if err := compiled.Validate(value); err != nil {
			return 0, 0, fmt.Errorf("validate Product fixture %s: %w", fixturePath, err)
		}
	}
	conformanceCases, err := validateConformanceSuite(manifest, documents)
	if err != nil {
		return 0, 0, err
	}

	var openAPIDocument any
	decoder := yaml.NewDecoder(bytes.NewReader(documents[openAPI.Path]))
	if err := decoder.Decode(&openAPIDocument); err != nil {
		return 0, 0, fmt.Errorf("decode Product OpenAPI: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return 0, 0, errors.New("Product OpenAPI contains trailing YAML documents")
	}
	root, ok := openAPIDocument.(map[string]any)
	if !ok || root["openapi"] != "3.1.0" {
		return 0, 0, errors.New("Product OpenAPI must be an OpenAPI 3.1.0 object")
	}
	info, ok := root["info"].(map[string]any)
	if !ok || info["version"] != manifest.ContractVersion {
		return 0, 0, errors.New("Product OpenAPI version does not match manifest")
	}
	paths, ok := root["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return 0, 0, errors.New("Product OpenAPI paths are required")
	}
	operationIDs := make(map[string]bool)
	operationCount := 0
	for route, value := range paths {
		if !strings.HasPrefix(route, "/api/v1/") {
			return 0, 0, fmt.Errorf("Product route %q is outside /api/v1", route)
		}
		item, ok := value.(map[string]any)
		if !ok {
			return 0, 0, fmt.Errorf("Product route %q is not an object", route)
		}
		for method, value := range item {
			if !map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "options": true, "head": true, "trace": true}[method] {
				continue
			}
			operation, ok := value.(map[string]any)
			if !ok {
				return 0, 0, fmt.Errorf("Product operation %s %s is not an object", method, route)
			}
			operationID, ok := operation["operationId"].(string)
			if !ok || strings.TrimSpace(operationID) == "" || operationIDs[operationID] {
				return 0, 0, fmt.Errorf("Product operation %s %s has missing or duplicate operationId", method, route)
			}
			operationIDs[operationID] = true
			operationCount++
		}
	}

	refs := make(map[string]bool)
	collectRefs(openAPIDocument, refs)
	for ref := range refs {
		base, fragment, _ := strings.Cut(ref, "#")
		if base == "" {
			continue
		}
		resolved := path.Clean(path.Join(path.Dir(openAPI.Path), base))
		dependency, ok := byPath[resolved]
		if !ok || dependency.Kind != "json-schema" {
			return 0, 0, fmt.Errorf("Product OpenAPI reference %q is not a manifested JSON Schema", ref)
		}
		if _, err := compiler.Compile(dependency.ID + "#" + fragment); err != nil {
			return 0, 0, fmt.Errorf("compile Product OpenAPI schema reference %q: %w", ref, err)
		}
	}
	return operationCount, conformanceCases, nil
}

func validateConformanceSuite(manifest manifestDocument, documents map[string][]byte) (int, error) {
	var suiteResource manifestResource
	for _, resource := range manifest.Resources {
		if resource.Kind == "conformance-suite" {
			if suiteResource.Path != "" {
				return 0, errors.New("Product Contract contains multiple conformance suites")
			}
			suiteResource = resource
		}
	}
	if suiteResource.Path == "" {
		return 0, errors.New("Product Contract conformance suite is required")
	}
	var suite conformanceSuite
	if err := decodeStrictJSON(documents[suiteResource.Path], &suite); err != nil {
		return 0, fmt.Errorf("decode Product conformance suite: %w", err)
	}
	if suite.SuiteID != "sandbox-runtime-product-v1alpha1" || suite.SuiteVersion != manifest.ContractVersion ||
		suite.ExecutionMode != "repository-go-test" || len(suite.Cases) == 0 {
		return 0, errors.New("invalid Product conformance suite identity")
	}
	seen := make(map[string]bool, len(suite.Cases))
	for _, candidate := range suite.Cases {
		if strings.TrimSpace(candidate.CaseID) == "" || seen[candidate.CaseID] ||
			!strings.HasPrefix(candidate.Package, "./product") || !strings.HasPrefix(candidate.Test, "Test") {
			return 0, fmt.Errorf("invalid Product conformance case %q", candidate.CaseID)
		}
		seen[candidate.CaseID] = true
	}
	return len(suite.Cases), nil
}

func validateSemanticDocument(document semanticDocument, manifest manifestDocument) error {
	if document.ContractNamespace != manifest.ContractNamespace || document.ContractVersion != manifest.ContractVersion ||
		document.Maturity != manifest.Maturity || len(document.Rules) == 0 {
		return errors.New("Product semantic-rules identity does not match manifest")
	}
	seenRules := make(map[string]bool, len(document.Rules))
	for _, rule := range document.Rules {
		if strings.TrimSpace(rule.ID) == "" || seenRules[rule.ID] || len(rule.Requires) == 0 || len(rule.Forbids) == 0 {
			return fmt.Errorf("invalid Product semantic rule %q", rule.ID)
		}
		seenRules[rule.ID] = true
		terms := make(map[string]bool, len(rule.Requires)+len(rule.Forbids))
		for _, list := range [][]string{rule.Requires, rule.Forbids} {
			for _, term := range list {
				if strings.TrimSpace(term) == "" || terms[term] {
					return fmt.Errorf("duplicate or empty term in Product semantic rule %q", rule.ID)
				}
				terms[term] = true
			}
		}
	}
	return nil
}

func collectRefs(value any, refs map[string]bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" {
				if ref, ok := child.(string); ok {
					refs[ref] = true
				}
			}
			collectRefs(child, refs)
		}
	case []any:
		for _, child := range typed {
			collectRefs(child, refs)
		}
	}
}

func validResourcePath(value string) bool {
	return fs.ValidPath(value) && value != "." && !strings.Contains(value, `\`) && !strings.HasPrefix(value, "compatibility/")
}

func readContractResource(root, relative string) ([]byte, error) {
	if !validResourcePath(relative) {
		return nil, fmt.Errorf("invalid Product Contract resource path %q", relative)
	}
	return readRegular(filepath.Join(root, ContractRoot, filepath.FromSlash(relative)))
}

func readRegular(filename string) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(resolved) != filepath.Clean(filename) {
		return nil, errors.New("resource path contains a symbolic link")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("resource is not a regular file")
	}
	if info.Size() > maxDocumentBytes {
		return nil, fmt.Errorf("resource exceeds %d bytes", maxDocumentBytes)
	}
	return os.ReadFile(filename)
}

func rawDigest(document []byte) string {
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:])
}

func prefixedDigest(document []byte) string { return "sha256:" + rawDigest(document) }

func decodeStrictJSON(document []byte, target any) error {
	if err := rejectDuplicateMembers(document); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func rejectDuplicateMembers(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate or invalid JSON member %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

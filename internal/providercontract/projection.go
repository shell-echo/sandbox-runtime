// Package providercontract validates the local Provider v1 wire projection
// against a separately supplied, locked Agent Contract checkout.
package providercontract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/shell-echo/sandbox-runtime/internal/contractlock"
	"go.yaml.in/yaml/v3"
)

const (
	maxContractDocumentBytes = 4 << 20
	maxExampleBytes          = 2 << 20
	schemaPathPrefix         = "../schemas/"
)

type manifestResource struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type Projection struct {
	contractRoot  string
	schemaNames   []string
	schemas       map[string]*jsonschema.Schema
	requestLimits map[string]int64
}

// Load verifies the source checkout before reading and compiling any projected
// OpenAPI Schema or example resource.
func Load(ctx context.Context, lockPath, sourceRoot string) (*Projection, error) {
	lock, err := contractlock.Load(lockPath)
	if err != nil {
		return nil, err
	}
	if _, err := contractlock.Verify(ctx, lock, sourceRoot); err != nil {
		return nil, fmt.Errorf("verify Contract before projection: %w", err)
	}

	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve Contract source root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve Contract source root: %w", err)
	}
	contractRoot, err := securePath(root, lock.Contract.Root)
	if err != nil {
		return nil, err
	}

	manifestPath, err := securePath(root, lock.Contract.ManifestPath)
	if err != nil {
		return nil, err
	}
	manifestData, err := readBounded(manifestPath, maxContractDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("read Contract manifest projection: %w", err)
	}
	var manifest struct {
		Resources []manifestResource `json:"resources"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("decode Contract manifest projection: %w", err)
	}

	openAPIPath, err := securePath(root, lock.Contract.OpenAPIPath)
	if err != nil {
		return nil, err
	}
	openAPIData, err := readBounded(openAPIPath, maxContractDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("read Provider OpenAPI projection: %w", err)
	}
	schemaNames, requestLimits, err := externalSchemaProjection(openAPIData)
	if err != nil {
		return nil, err
	}

	compiled, err := compileSchemas(contractRoot, manifest.Resources, schemaNames)
	if err != nil {
		return nil, err
	}
	return &Projection{
		contractRoot:  contractRoot,
		schemaNames:   schemaNames,
		schemas:       compiled,
		requestLimits: requestLimits,
	}, nil
}

func (p *Projection) RequestBodyLimits() map[string]int64 {
	result := make(map[string]int64, len(p.requestLimits))
	for schemaName, limit := range p.requestLimits {
		result[schemaName] = limit
	}
	return result
}

func (p *Projection) SchemaNames() []string {
	return append([]string(nil), p.schemaNames...)
}

func (p *Projection) Validate(schemaName string, document []byte) error {
	schema, ok := p.schemas[schemaName]
	if !ok {
		return fmt.Errorf("schema %q is outside the Provider OpenAPI projection", schemaName)
	}
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		return fmt.Errorf("decode projected JSON document: %w", err)
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("validate %s: %w", schemaName, err)
	}
	return nil
}

func (p *Projection) ReadExample(name string) ([]byte, error) {
	if !fs.ValidPath(name) || path.Base(name) != name {
		return nil, errors.New("example name must be one clean path segment")
	}
	examplePath, err := securePath(p.contractRoot, path.Join("examples/contracts", name))
	if err != nil {
		return nil, err
	}
	data, err := readBounded(examplePath, maxExampleBytes)
	if err != nil {
		return nil, fmt.Errorf("read Contract example %s: %w", name, err)
	}
	return data, nil
}

func externalSchemaProjection(openAPIData []byte) ([]string, map[string]int64, error) {
	var document any
	if err := yaml.Unmarshal(openAPIData, &document); err != nil {
		return nil, nil, fmt.Errorf("decode Provider OpenAPI: %w", err)
	}
	refs := make(map[string]struct{})
	collectYAMLRefs(document, refs)

	names := make([]string, 0, len(refs))
	for ref := range refs {
		if strings.HasPrefix(ref, "#/") {
			continue
		}
		if !strings.HasPrefix(ref, schemaPathPrefix) {
			return nil, nil, fmt.Errorf("Provider OpenAPI contains unsupported external reference %q", ref)
		}
		name := strings.TrimPrefix(ref, schemaPathPrefix)
		if !fs.ValidPath(name) || path.Base(name) != name || !strings.HasSuffix(name, ".schema.json") {
			return nil, nil, fmt.Errorf("Provider OpenAPI contains unsafe Schema reference %q", ref)
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, nil, errors.New("Provider OpenAPI has no external Schema projection")
	}
	sort.Strings(names)
	limits, err := openAPIRequestLimits(document)
	if err != nil {
		return nil, nil, err
	}
	return names, limits, nil
}

func openAPIRequestLimits(document any) (map[string]int64, error) {
	root, ok := document.(map[string]any)
	if !ok {
		return nil, errors.New("Provider OpenAPI root must be an object")
	}
	paths, ok := root["paths"].(map[string]any)
	if !ok {
		return nil, errors.New("Provider OpenAPI paths must be an object")
	}
	limits := make(map[string]int64)
	for route, pathValue := range paths {
		pathItem, ok := pathValue.(map[string]any)
		if !ok {
			continue
		}
		for method, operationValue := range pathItem {
			operation, ok := operationValue.(map[string]any)
			if !ok {
				continue
			}
			limitValue, hasLimit := operation["x-max-encoded-body-bytes"]
			if !hasLimit {
				continue
			}
			limit, ok := integerValue(limitValue)
			if !ok || limit <= 0 {
				return nil, fmt.Errorf("Provider OpenAPI %s %s has invalid encoded body limit", method, route)
			}
			requestBody, ok := operation["requestBody"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Provider OpenAPI %s %s has a limit without a request body", method, route)
			}
			content, ok := requestBody["content"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Provider OpenAPI %s %s request content is invalid", method, route)
			}
			mediaType, ok := content["application/json"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Provider OpenAPI %s %s lacks application/json", method, route)
			}
			schema, ok := mediaType["schema"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Provider OpenAPI %s %s request Schema is invalid", method, route)
			}
			ref, ok := schema["$ref"].(string)
			if !ok || !strings.HasPrefix(ref, schemaPathPrefix) {
				return nil, fmt.Errorf("Provider OpenAPI %s %s request Schema reference is invalid", method, route)
			}
			name := strings.TrimPrefix(ref, schemaPathPrefix)
			if _, duplicate := limits[name]; duplicate {
				return nil, fmt.Errorf("Provider OpenAPI request Schema %s has multiple encoded body limits", name)
			}
			limits[name] = limit
		}
	}
	return limits, nil
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed), true
		}
	}
	return 0, false
}

func collectYAMLRefs(value any, refs map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if key == "$ref" {
				if ref, ok := item.(string); ok {
					refs[ref] = struct{}{}
				}
			}
			collectYAMLRefs(item, refs)
		}
	case []any:
		for _, item := range typed {
			collectYAMLRefs(item, refs)
		}
	}
}

func compileSchemas(contractRoot string, resources []manifestResource, schemaNames []string) (map[string]*jsonschema.Schema, error) {
	byID := make(map[string]manifestResource)
	byPath := make(map[string]manifestResource)
	for _, resource := range resources {
		if resource.Kind != "json-schema" {
			continue
		}
		if !fs.ValidPath(resource.Path) || resource.ID == "" {
			return nil, fmt.Errorf("invalid JSON Schema manifest resource %q", resource.Path)
		}
		byID[resource.ID] = resource
		byPath[resource.Path] = resource
	}

	topLevel := make(map[string]manifestResource, len(schemaNames))
	queue := make([]manifestResource, 0, len(schemaNames))
	for _, name := range schemaNames {
		resource, ok := byPath[path.Join("schemas", name)]
		if !ok {
			return nil, fmt.Errorf("projected Schema %s is absent from the verified manifest", name)
		}
		topLevel[name] = resource
		queue = append(queue, resource)
	}

	documentByID := make(map[string]any)
	for len(queue) > 0 {
		resource := queue[0]
		queue = queue[1:]
		if _, loaded := documentByID[resource.ID]; loaded {
			continue
		}
		resourcePath, err := securePath(contractRoot, resource.Path)
		if err != nil {
			return nil, err
		}
		data, err := readBounded(resourcePath, maxContractDocumentBytes)
		if err != nil {
			return nil, fmt.Errorf("read projected Schema %s: %w", resource.Path, err)
		}
		var schemaDocument any
		if err := json.Unmarshal(data, &schemaDocument); err != nil {
			return nil, fmt.Errorf("decode projected Schema %s: %w", resource.Path, err)
		}
		object, ok := schemaDocument.(map[string]any)
		if !ok || object["$id"] != resource.ID {
			return nil, fmt.Errorf("Schema %s ID does not match verified manifest", resource.Path)
		}
		documentByID[resource.ID] = schemaDocument

		refs := make(map[string]struct{})
		collectJSONRefs(schemaDocument, refs)
		for ref := range refs {
			base := strings.SplitN(ref, "#", 2)[0]
			if base == "" {
				continue
			}
			var dependency manifestResource
			var found bool
			if strings.HasPrefix(base, "urn:") {
				dependency, found = byID[base]
			} else {
				dependencyPath := path.Clean(path.Join(path.Dir(resource.Path), base))
				dependency, found = byPath[dependencyPath]
			}
			if !found {
				return nil, fmt.Errorf("Schema %s references unmanifested resource %q", resource.Path, ref)
			}
			queue = append(queue, dependency)
		}
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	for id, document := range documentByID {
		if err := compiler.AddResource(id, document); err != nil {
			return nil, fmt.Errorf("register projected Schema %s: %w", id, err)
		}
	}

	compiled := make(map[string]*jsonschema.Schema, len(topLevel))
	for name, resource := range topLevel {
		schema, err := compiler.Compile(resource.ID)
		if err != nil {
			return nil, fmt.Errorf("compile projected Schema %s: %w", name, err)
		}
		compiled[name] = schema
	}
	return compiled, nil
}

func collectJSONRefs(value any, refs map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if key == "$ref" {
				if ref, ok := item.(string); ok {
					refs[ref] = struct{}{}
				}
			}
			collectJSONRefs(item, refs)
		}
	case []any:
		for _, item := range typed {
			collectJSONRefs(item, refs)
		}
	}
}

func securePath(root, relative string) (string, error) {
	if !fs.ValidPath(relative) || relative == "." {
		return "", fmt.Errorf("Contract path %q must be a clean relative slash path", relative)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return "", fmt.Errorf("resolve Contract path %s: %w", relative, err)
	}
	relativeToRoot, err := filepath.Rel(root, resolved)
	if err != nil || relativeToRoot == ".." || strings.HasPrefix(relativeToRoot, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("Contract path %s escapes its verified root", relative)
	}
	return resolved, nil
}

func readBounded(filePath string, limit int64) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Contract resource is not a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("Contract resource exceeds %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("Contract resource exceeds %d bytes", limit)
	}
	return data, nil
}

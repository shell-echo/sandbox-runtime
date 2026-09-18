package productwebclient

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

type operation struct {
	ID, Method, Path string
}

func Generate(openAPI []byte) ([]byte, error) {
	var document struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openAPI, &document); err != nil {
		return nil, fmt.Errorf("decode Product OpenAPI: %w", err)
	}
	var operations []operation
	for path, methods := range document.Paths {
		for method, definition := range methods {
			method = strings.ToUpper(method)
			if definition.OperationID == "" || (method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" && method != "PATCH") {
				continue
			}
			operations = append(operations, operation{ID: definition.OperationID, Method: method, Path: path})
		}
	}
	if len(operations) == 0 {
		return nil, fmt.Errorf("Product OpenAPI contains no operations")
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].ID < operations[j].ID })
	var output bytes.Buffer
	output.WriteString("// Code generated from the locked Product OpenAPI. DO NOT EDIT.\n")
	output.WriteString("export const productOperations = Object.freeze({\n")
	for _, item := range operations {
		fmt.Fprintf(&output, "  %q: Object.freeze({ method: %q, path: %q }),\n", item.ID, item.Method, item.Path)
	}
	output.WriteString("});\n\n")
	output.WriteString(`export async function callProduct(operationId, options = {}) {
  const operation = productOperations[operationId];
  if (!operation) throw new Error("Unknown Product operation");
  let path = operation.path;
  for (const [name, value] of Object.entries(options.path || {})) {
    path = path.replace("{" + name + "}", encodeURIComponent(value));
  }
  if (path.includes("{")) throw new Error("Missing Product path parameter");
  const query = new URLSearchParams(options.query || {});
  const response = await fetch("/web" + path + (query.size ? "?" + query : ""), {
    method: operation.method,
    credentials: "same-origin",
    headers: options.headers || {},
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const document = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    const error = new Error(document?.message || "Product request failed");
    error.code = document?.code || "PRODUCT_REQUEST_FAILED";
    error.status = response.status;
    throw error;
  }
  return document;
}
`)
	return output.Bytes(), nil
}

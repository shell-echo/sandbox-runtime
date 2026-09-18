package productboundary

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/shell-echo/sandbox-runtime/"

func TestProductionImportsPreserveProductProviderBoundaries(t *testing.T) {
	root := repositoryRoot(t)
	for _, directory := range []string{"product", "productapi", "guestagent", "provider", "providerapi", "driver", "instance", "gateway"} {
		path := filepath.Join(root, directory)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if err := filepath.WalkDir(path, func(filePath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(filePath) != ".go" || strings.HasSuffix(filePath, "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, filePath)
			if err != nil {
				return err
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), filePath, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imported := range parsed.Imports {
				pathValue, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return err
				}
				if forbiddenProductionImport(filepath.ToSlash(relative), pathValue) {
					t.Errorf("%s imports forbidden authority %s", filepath.ToSlash(relative), pathValue)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func forbiddenProductionImport(file string, imported string) bool {
	switch {
	case strings.HasPrefix(file, "product/adapter/provider/"):
		return hasAnyPackage(imported,
			modulePath+"provider", modulePath+"providerapi", modulePath+"driver",
			modulePath+"instance", modulePath+"gateway",
		) && !packageOrChild(imported, modulePath+"providerapi/v1")
	case strings.HasPrefix(file, "product/adapter/"):
		return hasAnyPackage(imported, modulePath+"provider", modulePath+"providerapi", modulePath+"driver", modulePath+"instance")
	case strings.HasPrefix(file, "product/"):
		return hasAnyPackage(imported,
			modulePath+"provider", modulePath+"providerapi", modulePath+"driver",
			modulePath+"instance", modulePath+"gateway", modulePath+"product/adapter",
			"github.com/gin-gonic/gin", "github.com/jackc/pgx",
		)
	case strings.HasPrefix(file, "productapi/"):
		return hasAnyPackage(imported,
			modulePath+"provider", modulePath+"providerapi", modulePath+"driver",
			modulePath+"instance", modulePath+"gateway", modulePath+"product/adapter",
			"github.com/jackc/pgx",
		)
	case strings.HasPrefix(file, "guestagent/"):
		return hasAnyPackage(imported,
			modulePath+"product/adapter", modulePath+"provider", modulePath+"providerapi",
			modulePath+"driver", modulePath+"instance",
		)
	case hasAnyPrefix(file, "provider/", "providerapi/", "driver/", "instance/", "gateway/"):
		return hasAnyPackage(imported, modulePath+"product", modulePath+"productapi", modulePath+"guestagent")
	default:
		return false
	}
}

func hasAnyPackage(value string, packages ...string) bool {
	for _, packagePath := range packages {
		if packageOrChild(value, packagePath) {
			return true
		}
	}
	return false
}

func packageOrChild(value, packagePath string) bool {
	return value == packagePath || strings.HasPrefix(value, packagePath+"/")
}

func hasAnyPrefix(value string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve boundary test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

func TestForbiddenProductionImportRules(t *testing.T) {
	tests := []struct {
		file     string
		imported string
		want     bool
	}{
		{"product/application.go", modulePath + "provider", true},
		{"product/application.go", modulePath + "provider/lifecycle", true},
		{"product/application.go", modulePath + "product/adapter/postgres", true},
		{"product/application.go", "github.com/jackc/pgx/v5", true},
		{"product/adapter/postgres/store.go", "github.com/jackc/pgx/v5", false},
		{"product/adapter/postgres/store.go", modulePath + "providerapi/v1", true},
		{"product/adapter/provider/client.go", modulePath + "providerapi/v1", false},
		{"product/adapter/provider/client.go", modulePath + "provider/lifecycle", true},
		{"productapi/http.go", modulePath + "product", false},
		{"productapi/http.go", modulePath + "product/adapter/postgres", true},
		{"provider/model.go", modulePath + "product", true},
		{"gateway/model.go", modulePath + "product/session", true},
		{"guestagent/client.go", modulePath + "providerapi", true},
	}
	for _, test := range tests {
		if got := forbiddenProductionImport(test.file, test.imported); got != test.want {
			t.Errorf("forbiddenProductionImport(%q, %q) = %t; want %t", test.file, test.imported, got, test.want)
		}
	}
}

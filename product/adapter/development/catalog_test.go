package development

import (
	"context"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/product"
)

func TestLockedCatalogIsImmutableAndNondisclosing(t *testing.T) {
	catalog := LockedCatalog{}
	first, err := catalog.Get(context.Background(), product.DevelopmentTemplateID)
	if err != nil || first.Validate() != nil {
		t.Fatalf("template=%+v err=%v", first, err)
	}
	second, _ := catalog.Get(context.Background(), product.DevelopmentTemplateID)
	if first.Revision != second.Revision || first.Image != second.Image || !strings.Contains(first.Image, "@sha256:") {
		t.Fatalf("template selection drifted: first=%+v second=%+v", first, second)
	}
	if strings.Contains(first.Image, "token") || strings.Contains(first.Image, "/Users/") || strings.Contains(first.Image, "/var/") {
		t.Fatalf("template exposed private state: %+v", first)
	}
	if _, err := catalog.Get(context.Background(), "mutable-latest"); err == nil {
		t.Fatal("unknown template was accepted")
	}
}

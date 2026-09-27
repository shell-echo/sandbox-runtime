package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
	browserreferencememory "github.com/shell-echo/sandbox-runtime/provider/browser/reference/repository/memory"
)

func TestProductionBrowserShutdownRevokesBeforeExactAllocationCleanup(t *testing.T) {
	now := time.Now().UTC()
	record := browserShutdownRecord(t, now, providerbrowser.StatusRunning, now.Add(30*time.Second))
	registry := browserreferencememory.NewRegistry()
	registered, err := browserreference.NewRecord("ref:browser-session:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", record, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Create(context.Background(), registered); err != nil {
		t.Fatal(err)
	}
	order := make([]string, 0, 2)
	runtime := &browserShutdownRuntime{order: &order}
	application := &productionBrowserApplication{sessions: &browserShutdownAuthority{records: []providerbrowser.Record{record}},
		references: &browserShutdownReferenceStore{Store: registry, order: &order}, runtime: runtime,
		cleanupTimeout: time.Second}
	if err := application.Close(); err != nil {
		t.Fatal(err)
	}
	if err := application.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if got := strings.Join(order, ","); got != "revoke,cleanup" {
		t.Fatalf("production Browser close ordering = %q", got)
	}
	if runtime.receipt != record.Allocation.Receipt {
		t.Fatalf("production cleanup receipt = %#v", runtime.receipt)
	}
}

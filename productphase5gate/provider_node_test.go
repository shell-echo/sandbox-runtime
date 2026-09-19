//go:build phase5desktopgate

package productphase5gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	productprovider "github.com/shell-echo/sandbox-runtime/product/adapter/provider"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type providerFixture struct {
	mu         sync.RWMutex
	operations map[string]providerRecord
	references map[string]providerRecord
	gateKey    string
}

type providerRecord struct {
	Operation  providerv1.Operation
	SessionID  string
	Reference  string
	ExpiresAt  time.Time
	Generation int64
	Active     bool
}

type privateDesktopResolution struct {
	Reference  string    `json:"reference"`
	SandboxID  string    `json:"sandbox_id"`
	SessionID  string    `json:"session_id"`
	Generation int64     `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func runProviderNode(config nodeConfig) error {
	fixture := &providerFixture{operations: make(map[string]providerRecord), references: make(map[string]providerRecord), gateKey: config.GateKey}
	codeMux := http.NewServeMux()
	codeMux.HandleFunc("/healthz", healthOK)
	codeMux.HandleFunc("/v1/capabilities", fixture.codeCapabilities)
	codeMux.HandleFunc("/v1/sandboxes", fixture.createSandbox)
	codeMux.HandleFunc("/v1/sandboxes/", fixture.sandboxMutation)
	codeMux.HandleFunc("/v1/operations/", fixture.operationRead)
	desktopMux := http.NewServeMux()
	desktopMux.HandleFunc("/healthz", healthOK)
	desktopMux.HandleFunc("/v1/capabilities", fixture.desktopCapabilities)
	desktopMux.HandleFunc("/v1/sandboxes", fixture.createSandbox)
	desktopMux.HandleFunc("/v1/sandboxes/", fixture.sandboxMutation)
	desktopMux.HandleFunc("/v1/operations/", fixture.operationRead)
	desktopMux.HandleFunc("/gate/desktop/resolve", fixture.resolveDesktop)
	return serveProviderPair(config.ProviderAddress, codeMux, config.DesktopProviderAddress, desktopMux)
}

func healthOK(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method", http.StatusMethodNotAllowed)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func (f *providerFixture) codeCapabilities(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(writer, http.StatusOK, providerv1.Capabilities{
		ProviderRevisionID: productprovider.LockedProviderRevision,
		APIVersion:         providerv1.APIVersionV1,
		Capabilities: []providerv1.Capability{
			{ID: providerv1.CapabilityExec, Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}},
			{ID: providerv1.CapabilityTerminal, Versions: []string{"1.0.0"}, Profiles: []string{"terminal-v1"}},
			{ID: providerv1.CapabilityTerminalControl, Versions: []string{"1.0.0"}, Profiles: []string{"terminal-control-v1"}},
		},
		RuntimeProfiles: []providerv1.RuntimeProfile{{ID: "coding-shell-v1", IsolationClass: providerv1.IsolationContainer, Architecture: []providerv1.Architecture{releaseArchitecture()}, CapabilityProfileIDs: []string{"exec-v1", "terminal-v1", "terminal-control-v1"}}},
		Limits:          providerv1.ProviderLimits{MaxCPUMillis: 4000, MaxMemoryBytes: 8 << 30, MaxEphemeralStorageBytes: 16 << 30, MaxLeaseSeconds: 86400, MaxExecSeconds: 3600},
	})
}

func (f *providerFixture) desktopCapabilities(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method", http.StatusMethodNotAllowed)
		return
	}
	workspaceBytes := int64(16 << 30)
	writeJSON(writer, http.StatusOK, providerv1.Capabilities{
		ProviderRevisionID: productprovider.LockedDesktopProviderRevision,
		APIVersion:         providerv1.APIVersionV1,
		Capabilities:       []providerv1.Capability{{ID: providerv1.CapabilityDesktop, Versions: []string{product.DesktopCapabilityVersion}, Profiles: []string{product.DesktopCapabilityProfile}}},
		RuntimeProfiles: []providerv1.RuntimeProfile{{ID: product.DesktopSlotProfile, IsolationClass: providerv1.IsolationContainer,
			RuntimeClassName: desktopimage.RuntimeClassName, Architecture: []providerv1.Architecture{providerv1.ArchitectureAMD64, providerv1.ArchitectureARM64}, CapabilityProfileIDs: []string{product.DesktopCapabilityProfile}}},
		Limits: providerv1.ProviderLimits{MaxCPUMillis: 16000, MaxMemoryBytes: 16 << 30, MaxEphemeralStorageBytes: 32 << 30, MaxWorkspaceBytes: &workspaceBytes, MaxLeaseSeconds: 86400},
	})
}

func (f *providerFixture) createSandbox(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !protected(request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input providerv1.CreateRequest
	if decodeStrictBody(request.Body, &input) != nil || input.OperationID == "" || input.Spec.SandboxID == "" {
		http.Error(writer, "invalid", http.StatusBadRequest)
		return
	}
	record := providerRecord{Operation: providerOperation(input.OperationID, input.AttemptID, input.Spec.SandboxID, input.FencingToken, providerv1.OperationCreate)}
	f.mu.Lock()
	f.operations[input.OperationID] = record
	f.mu.Unlock()
	writeJSON(writer, http.StatusAccepted, record.Operation)
}

func (f *providerFixture) sandboxMutation(writer http.ResponseWriter, request *http.Request) { //nolint:cyclop
	if request.Method != http.MethodPost || !protected(request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	sandboxID := sandboxFromPath(request.URL.Path)
	switch {
	case strings.HasSuffix(request.URL.Path, "/desktop-sessions"):
		var input providerv1.DesktopSessionOpenRequest
		if decodeStrictBody(request.Body, &input) != nil || input.ExpectedGeneration < 1 || input.CapabilityProfileID != product.DesktopCapabilityProfile {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, input.ExpiresAt)
		if err != nil || !expiresAt.After(time.Now()) {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		reference := "ref:desktop-session:" + input.OperationID
		record := providerRecord{Operation: providerOperation(input.OperationID, input.AttemptID, sandboxID, input.FencingToken, providerv1.OperationOpenDesktopSession), SessionID: input.DesktopSessionID, Reference: reference, ExpiresAt: expiresAt.UTC(), Generation: input.ExpectedGeneration, Active: true}
		f.mu.Lock()
		f.operations[input.OperationID], f.references[reference] = record, record
		f.mu.Unlock()
		writeJSON(writer, http.StatusAccepted, record.Operation)
	case strings.HasSuffix(request.URL.Path, ":close"):
		var input providerv1.DesktopSessionCloseRequest
		if decodeStrictBody(request.Body, &input) != nil || input.ExpectedGeneration < 1 || input.ConnectionGeneration < 1 {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		record := providerRecord{Operation: providerOperation(input.OperationID, input.AttemptID, sandboxID, input.FencingToken, providerv1.OperationCloseDesktopSession)}
		f.mu.Lock()
		f.operations[input.OperationID] = record
		for reference, current := range f.references {
			if current.SessionID == input.DesktopSessionID && current.Operation.SandboxID == sandboxID {
				delete(f.references, reference)
			}
		}
		f.mu.Unlock()
		writeJSON(writer, http.StatusAccepted, record.Operation)
	case strings.HasSuffix(request.URL.Path, ":terminate"):
		var input providerv1.TerminateRequest
		if decodeStrictBody(request.Body, &input) != nil {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		record := providerRecord{Operation: providerOperation(input.OperationID, input.AttemptID, sandboxID, input.FencingToken, providerv1.OperationTerminate)}
		f.mu.Lock()
		f.operations[input.OperationID] = record
		for reference, current := range f.references {
			if current.Operation.SandboxID == sandboxID {
				delete(f.references, reference)
			}
		}
		f.mu.Unlock()
		writeJSON(writer, http.StatusAccepted, record.Operation)
	default:
		http.NotFound(writer, request)
	}
}

func (f *providerFixture) operationRead(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !protected(request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	value := strings.TrimPrefix(request.URL.Path, "/v1/operations/")
	handoff := strings.HasSuffix(value, "/desktop-session")
	operationID := strings.TrimSuffix(value, "/desktop-session")
	f.mu.RLock()
	record, ok := f.operations[operationID]
	f.mu.RUnlock()
	if !ok {
		http.NotFound(writer, request)
		return
	}
	if handoff {
		if record.Reference == "" || !record.Active {
			http.NotFound(writer, request)
			return
		}
		writeJSON(writer, http.StatusOK, providerv1.DesktopSessionHandoff{OperationID: record.Operation.OperationID, AttemptID: record.Operation.AttemptID,
			FencingToken: record.Operation.FencingToken, SandboxID: record.Operation.SandboxID, DesktopSessionID: record.SessionID,
			CapabilityProfileID: product.DesktopCapabilityProfile, Protocol: providerv1.DesktopProtocolWebRTC,
			MediaProfileID: "desktop-media-v1", ControlProfileID: "desktop-control-v1", InternalEndpointReference: record.Reference,
			ConnectionGeneration: record.Generation, ExpiresAt: record.ExpiresAt.Format(time.RFC3339Nano)})
		return
	}
	operation := record.Operation
	operation.Status, operation.ObservedAt = providerv1.OperationSucceeded, time.Now().UTC().Format(time.RFC3339Nano)
	writeJSON(writer, http.StatusOK, operation)
}

func (f *providerFixture) resolveDesktop(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.Header.Get("X-Gate-Key") != f.gateKey {
		http.NotFound(writer, request)
		return
	}
	reference, err := url.QueryUnescape(request.URL.Query().Get("reference"))
	if err != nil || reference == "" {
		http.NotFound(writer, request)
		return
	}
	f.mu.RLock()
	record, ok := f.references[reference]
	f.mu.RUnlock()
	if !ok || !record.Active || !record.ExpiresAt.After(time.Now().UTC()) {
		http.NotFound(writer, request)
		return
	}
	writeJSON(writer, http.StatusOK, privateDesktopResolution{Reference: reference, SandboxID: record.Operation.SandboxID, SessionID: record.SessionID, Generation: record.Generation, ExpiresAt: record.ExpiresAt})
}

func providerOperation(operationID, attemptID, sandboxID string, fence int64, kind providerv1.OperationType) providerv1.Operation {
	return providerv1.Operation{OperationID: operationID, AttemptID: attemptID, FencingToken: fence, SandboxID: sandboxID, Type: kind,
		Status: providerv1.OperationAccepted, ProviderOperationID: "provider-" + operationID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}

func sandboxFromPath(path string) string {
	value := strings.TrimPrefix(path, "/v1/sandboxes/")
	if index := strings.IndexAny(value, "/:"); index >= 0 {
		return value[:index]
	}
	return value
}

func protected(request *http.Request) bool {
	return strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") && request.Header.Get("X-Sandbox-Runtime-Admission-Context") != ""
}

func decodeStrictBody(body io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func serveProviderPair(firstAddress string, first http.Handler, secondAddress string, second http.Handler) error {
	firstListener, err := net.Listen("tcp", firstAddress)
	if err != nil {
		return err
	}
	defer firstListener.Close()
	secondListener, err := net.Listen("tcp", secondAddress)
	if err != nil {
		return err
	}
	defer secondListener.Close()
	servers := []*http.Server{{Handler: first, ReadHeaderTimeout: 2 * time.Second}, {Handler: second, ReadHeaderTimeout: 2 * time.Second}}
	done := make(chan error, 2)
	go func() { done <- servers[0].Serve(firstListener) }()
	go func() { done <- servers[1].Serve(secondListener) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case serveErr := <-done:
		return serveErr
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, server := range servers {
			if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
				return shutdownErr
			}
		}
		return nil
	}
}

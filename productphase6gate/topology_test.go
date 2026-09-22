//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
)

func startGateTopology(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	startGateCredentialController(t, ctx, environment)
	startGateBreakGlassController(t, ctx, environment)
	runGateMigrations(t, ctx, environment)
	startRuntimeMaterialAgents(t, ctx, environment)
	startDependency := func(name, binary, authority string, port int) {
		process := startGateProcess(t, ctx, name, binary, filepath.Join(environment.paths.directory, name+".log"), "serve", authority)
		environment.dependencies = append(environment.dependencies, process)
		t.Cleanup(func() { bestEffortStopGateProcess(process) })
		waitTCP(t, process, fmt.Sprintf("127.0.0.1:%d", port), 30*time.Second)
	}
	startDependency("browser-backend", environment.paths.browserBackendBin, environment.paths.browserBackendAuth, environment.ports.browserBackend)

	provider := startConfiguredRole(t, ctx, environment, "provider", environment.paths.providerConfig, "provider", "serve")
	waitHTTPStatus(t, provider, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/livez", environment.ports.providerProbe), http.StatusNoContent, 45*time.Second)
	waitHTTPStatus(t, provider, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.providerProbe), http.StatusNoContent, 45*time.Second)
	markReady(provider)
	waitFor(t, 30*time.Second, "Provider Desktop broker mux socket", func() bool {
		info, err := os.Lstat(environment.paths.brokerSocket)
		return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode()&os.ModeSymlink == 0
	})
	// The Desktop backend validates the Provider-owned broker socket before it
	// binds. Start it only after the mux has established that authority boundary.
	startDependency("desktop-backend", environment.paths.desktopBackendBin, environment.paths.desktopBackendAuth, environment.ports.desktopBackend)

	product := startConfiguredRole(t, ctx, environment, "product", environment.paths.productConfig, "product", "serve")
	waitHTTPStatus(t, product, productClient(environment), fmt.Sprintf("https://127.0.0.1:%d/readyz", environment.ports.product), http.StatusOK, 45*time.Second)
	markReady(product)

	gateway := startConfiguredRole(t, ctx, environment, "gateway", environment.paths.gatewayConfig, "gateway", "serve")
	waitHTTPStatus(t, gateway, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.gatewayProbe), http.StatusNoContent, 45*time.Second)
	markReady(gateway)

	guest := startConfiguredRole(t, ctx, environment, "guest", environment.paths.guestConfig, "guest", "serve")
	waitHTTPStatus(t, guest, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.guestProbe), http.StatusNoContent, 45*time.Second)
	waitFor(t, 10*time.Second, "Guest development health round trip", func() bool {
		_, healthResponses, connected := environment.guest.snapshot()
		return connected && healthResponses >= 1
	})
	markReady(guest)

	browser := startConfiguredRole(t, ctx, environment, "browser", environment.paths.browserConfig, "browser", "serve")
	waitHTTPStatus(t, browser, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.browserProbe), http.StatusNoContent, 45*time.Second)
	markReady(browser)

	desktop := startConfiguredRole(t, ctx, environment, "desktop", environment.paths.desktopConfig, "desktop", "serve")
	waitHTTPStatus(t, desktop, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/livez", environment.ports.desktopProbe), http.StatusNoContent, 45*time.Second)
	waitHTTPStatus(t, desktop, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.desktopProbe), http.StatusServiceUnavailable, 15*time.Second)
}

func startConfiguredRole(t *testing.T, ctx context.Context, environment *gateEnvironment, name, config string, arguments ...string) *gateProcess {
	t.Helper()
	commandArguments := append([]string{"--config", config}, arguments...)
	instance := len(environment.roleHistory[name]) + 1
	process := startGateProcess(t, ctx, name, environment.paths.binary, filepath.Join(environment.paths.directory, fmt.Sprintf("%s-%d.log", name, instance)), commandArguments...)
	environment.roles[name] = process
	environment.roleHistory[name] = append(environment.roleHistory[name], process)
	t.Cleanup(func() { bestEffortStopGateProcess(process) })
	return process
}

func stopGateTopology(t *testing.T, environment *gateEnvironment) {
	t.Helper()
	for _, name := range []string{"desktop", "browser", "guest", "gateway", "provider", "product"} {
		stopGateProcess(t, environment.roles[name], 15*time.Second)
	}
	for index := len(environment.dependencies) - 1; index >= 0; index-- {
		stopGateProcess(t, environment.dependencies[index], 15*time.Second)
	}
}

func assertProductBoundary(t *testing.T, environment *gateEnvironment) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/v1/capabilities", environment.ports.product), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+signProductToken(t, environment.productToken))
	response, err := productClient(environment).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		t.Fatalf("Product capabilities status=%d body=%s", response.StatusCode, body)
	}
	var document productapiv1.CapabilityDocument
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if len(document.Capabilities) != 1 || document.Capabilities[0].CapabilityID != "product.workspace" || document.Capabilities[0].Readiness != "unavailable" || len(document.Capabilities[0].ProtocolProfiles) != 0 {
		t.Fatalf("Product boundary capabilities=%#v", document.Capabilities)
	}
}

func assertGatewayBoundary(t *testing.T, environment *gateEnvironment) {
	t.Helper()
	client := gatewayClient(environment)
	for _, path := range []string{"/browser/automation", "/browser/live", "/desktop/connect"} {
		response, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d%s", environment.ports.gateway, path))
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), `"code":"PRODUCT_CAPABILITY_UNAVAILABLE"`) || strings.Contains(string(body), "provider") || strings.Contains(string(body), "docker") {
			t.Fatalf("Gateway deferred route %s status=%d body=%q err=%v", path, response.StatusCode, body, readErr)
		}
	}
	response, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/capabilities", environment.ports.gateway))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var projection struct {
		SchemaVersion     string `json:"schema_version"`
		Terminal          string `json:"terminal"`
		BrowserAutomation string `json:"browser_automation"`
		BrowserLive       string `json:"browser_live"`
		DesktopLive       string `json:"desktop_live"`
		Reason            string `json:"reason"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&projection) != nil || projection.Terminal != "enabled" || projection.BrowserAutomation != "authority_unavailable" || projection.BrowserLive != "authority_unavailable" || projection.DesktopLive != "authority_unavailable" {
		t.Fatalf("Gateway capabilities status=%d projection=%#v", response.StatusCode, projection)
	}
}

func waitTCP(t *testing.T, process *gateProcess, address string, timeout time.Duration) {
	t.Helper()
	waitFor(t, timeout, process.name+" listener", func() bool {
		select {
		case err := <-process.done:
			t.Fatalf("%s stopped before listener became ready: %v; log=%s", process.name, err, gateLog(process))
		default:
		}
		connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = connection.Close()
		return true
	})
}

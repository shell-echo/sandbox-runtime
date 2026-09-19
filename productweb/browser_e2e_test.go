//go:build browser

package productweb

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

func TestBrowserAuthenticatedSessionAndProductRead(t *testing.T) {
	chrome := os.Getenv("SANDBOX_RUNTIME_CHROME")
	if chrome == "" && runtime.GOOS == "darwin" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	if _, err := os.Stat(chrome); err != nil {
		t.Skip("Chrome is not available; set SANDBOX_RUNTIME_CHROME")
	}
	actor := product.ActorRef{Type: product.ActorHuman, ID: "browser-e2e"}
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{{Token: webTestBearer, Principal: productapi.Principal{TenantID: "tenant-browser", Actor: actor, Role: productapi.RoleOwner}}})
	if err != nil {
		t.Fatal(err)
	}
	api := &apiSpy{}
	var web *Server
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/browser-e2e.html":
			securityHeaders(writer.Header(), true)
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = writer.Write([]byte(`<!doctype html><html><body><main id="result">RUNNING</main><script src="/browser-e2e.js"></script></body></html>`))
		case "/browser-e2e.js":
			writer.Header().Set("Content-Type", "text/javascript")
			_, _ = fmt.Fprintf(writer, `(async()=>{try{const login=await fetch("/web/session",{method:"POST",credentials:"same-origin",headers:{Authorization:%q}});const session=await login.json();if(!login.ok||!session.csrf_token)throw new Error("login");location.replace("/")}catch(error){document.querySelector("#result").textContent="BROWSER_E2E_FAIL:"+error.message}})();`, "Bearer "+webTestBearer)
		default:
			web.ServeHTTP(writer, request)
		}
	})
	testServer := httptest.NewUnstartedServer(handler)
	origin := "https://" + testServer.Listener.Addr().String()
	web, err = New(Options{ProductAPI: api, Authenticator: authenticator, SessionEncryptionKey: bytes.Repeat([]byte{9}, 32), PublicOrigin: origin, SessionTTL: 10 * time.Minute, IdleTTL: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	testServer.StartTLS()
	defer testServer.Close()
	profile := t.TempDir()
	commandContext, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, chrome,
		"--headless", "--disable-gpu", "--disable-extensions", "--disable-default-apps",
		"--disable-background-networking", "--disable-component-update", "--disable-sync",
		"--no-first-run", "--no-default-browser-check", "--no-proxy-server",
		"--ignore-certificate-errors", "--user-data-dir="+filepath.Join(profile, "chrome"),
		"--virtual-time-budget=5000", "--dump-dom", testServer.URL+"/browser-e2e.html",
	)
	output, err := command.CombinedOutput()
	document := string(output)
	desktopTab := regexp.MustCompile(`<button id="desktop-tab"[^>]*>`).FindString(document)
	if !strings.Contains(document, `id="browser-tab"`) || desktopTab == "" || !strings.Contains(desktopTab, `data-capability-ready="true"`) || strings.Contains(desktopTab, " disabled") || !strings.Contains(document, "browser-e2e · owner") {
		t.Fatalf("headless Chrome failed: %v\n%s", err, output)
	}
	if api.calls != 2 || api.auth != "Bearer "+webTestBearer || api.cookies != "" {
		t.Fatalf("browser Product call = %#v", api)
	}
}

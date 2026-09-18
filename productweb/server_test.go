package productweb

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const webTestBearer = "browser-product-token-0000000000000000000001"

type apiSpy struct {
	mu      sync.Mutex
	calls   int
	method  string
	path    string
	auth    string
	cookies string
}

func (s *apiSpy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.method = request.Method
	s.path = request.URL.RequestURI()
	s.auth = request.Header.Get("Authorization")
	s.cookies = request.Header.Get("Cookie")
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, `{"items":[]}`)
}

func TestAuthenticatedBrowserSessionProxiesWithoutExposingBearer(t *testing.T) {
	server, api, _ := newWebServer(t, nil)
	login := webRequest(http.MethodPost, "/web/session", "")
	login.Header.Set("Origin", "https://product.example.test")
	login.Header.Set("Authorization", "Bearer "+webTestBearer)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, login)
	if response.Code != http.StatusCreated {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), webTestBearer) || strings.Contains(response.Header().Get("Set-Cookie"), webTestBearer) {
		t.Fatal("bearer credential was exposed to the browser")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
		t.Fatalf("session cookie = %#v", cookies)
	}
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil || len(session.CSRFToken) < 32 {
		t.Fatalf("session document=%s error=%v", response.Body.String(), err)
	}

	proxied := webRequest(http.MethodGet, "/web/api/v1/workspaces?limit=5", "")
	proxied.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	server.ServeHTTP(response, proxied)
	if response.Code != http.StatusOK || api.calls != 1 || api.method != http.MethodGet || api.path != "/api/v1/workspaces?limit=5" || api.auth != "Bearer "+webTestBearer || api.cookies != "" {
		t.Fatalf("proxy response=%d api=%#v body=%s", response.Code, api, response.Body.String())
	}

	mutation := webRequest(http.MethodPost, "/web/api/v1/workspaces", `{}`)
	mutation.AddCookie(cookies[0])
	mutation.Header.Set("Origin", "https://product.example.test")
	mutation.Header.Set("X-CSRF-Token", session.CSRFToken)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, mutation)
	if response.Code != http.StatusOK || api.calls != 2 || api.method != http.MethodPost {
		t.Fatalf("mutation response=%d calls=%d", response.Code, api.calls)
	}

	server.sessions.mu.Lock()
	for _, stored := range server.sessions.records {
		if bytes.Contains(stored.encryptedToken, []byte(webTestBearer)) {
			server.sessions.mu.Unlock()
			t.Fatal("session store retained plaintext bearer")
		}
	}
	server.sessions.mu.Unlock()
}

func TestBrowserSessionRejectsOriginCSRFAndAmbiguousCookies(t *testing.T) {
	server, api, _ := newWebServer(t, nil)
	request := webRequest(http.MethodPost, "/web/session", "")
	request.Header.Set("Authorization", "Bearer "+webTestBearer)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("originless login status=%d", response.Code)
	}

	cookie, csrf := loginWebSession(t, server)
	tests := []struct {
		name   string
		origin string
		csrf   string
		second bool
	}{
		{name: "missing csrf", origin: "https://product.example.test"},
		{name: "wrong csrf", origin: "https://product.example.test", csrf: "wrong"},
		{name: "wrong origin", origin: "https://evil.example", csrf: csrf},
		{name: "duplicate cookie", origin: "https://product.example.test", csrf: csrf, second: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := webRequest(http.MethodPost, "/web/api/v1/workspaces", `{}`)
			request.AddCookie(cookie)
			if test.second {
				request.AddCookie(cookie)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.csrf != "" {
				request.Header.Set("X-CSRF-Token", test.csrf)
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden && response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if api.calls != 0 {
		t.Fatalf("rejected requests reached Product API: %d", api.calls)
	}
}

func TestSessionRotationExpiryAndLogout(t *testing.T) {
	now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	server, _, advance := newWebServer(t, &now)
	cookie, csrf := loginWebSession(t, server)
	bootstrap := webRequest(http.MethodGet, "/web/session", "")
	bootstrap.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, bootstrap)
	if response.Code != http.StatusOK {
		t.Fatalf("bootstrap status=%d body=%s", response.Code, response.Body.String())
	}
	var rotated struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &rotated)
	if rotated.CSRFToken == csrf || rotated.CSRFToken == "" {
		t.Fatal("bootstrap did not rotate CSRF token")
	}
	logout := webRequest(http.MethodDelete, "/web/session", "")
	logout.AddCookie(cookie)
	logout.Header.Set("Origin", "https://product.example.test")
	logout.Header.Set("X-CSRF-Token", rotated.CSRFToken)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, logout)
	if response.Code != http.StatusNoContent || response.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("logout status=%d cookies=%#v", response.Code, response.Result().Cookies())
	}

	cookie, _ = loginWebSession(t, server)
	advance(3 * time.Minute)
	expired := webRequest(http.MethodGet, "/web/session", "")
	expired.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, expired)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired session status=%d", response.Code)
	}
}

func TestStaticUIHasStrictSecurityAndAccessibilityLandmarks(t *testing.T) {
	server, _, _ := newWebServer(t, nil)
	request := webRequest(http.MethodGet, "/", "")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("static status=%d", response.Code)
	}
	csp := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "'unsafe-inline'") || response.Header().Get("Strict-Transport-Security") == "" || response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers=%v", response.Header())
	}
	html := response.Body.String()
	for _, required := range []string{`<main id="main">`, `role="status"`, `aria-live="polite"`, `for="bearer"`, `type="module" src="/assets/app.js"`} {
		if !strings.Contains(html, required) {
			t.Fatalf("static UI missing %q", required)
		}
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "style=") {
		t.Fatal("static UI contains inline executable/style content")
	}
}

func newWebServer(t *testing.T, controlledNow *time.Time) (*Server, *apiSpy, func(time.Duration)) {
	t.Helper()
	actor := product.ActorRef{Type: product.ActorHuman, ID: "actor-1"}
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{{Token: webTestBearer, Principal: productapi.Principal{TenantID: "tenant-1", Actor: actor, Role: productapi.RoleOwner}}})
	if err != nil {
		t.Fatal(err)
	}
	api := &apiSpy{}
	clock := time.Now
	if controlledNow != nil {
		clock = func() time.Time { return *controlledNow }
	}
	server, err := New(Options{ProductAPI: api, Authenticator: authenticator, SessionEncryptionKey: bytes.Repeat([]byte{7}, 32), PublicOrigin: "https://product.example.test", SessionTTL: 10 * time.Minute, IdleTTL: 2 * time.Minute, MaxSessions: 10, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return server, api, func(duration time.Duration) {
		if controlledNow != nil {
			*controlledNow = controlledNow.Add(duration)
		}
	}
}

func loginWebSession(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	request := webRequest(http.MethodPost, "/web/session", "")
	request.Header.Set("Origin", "https://product.example.test")
	request.Header.Set("Authorization", "Bearer "+webTestBearer)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	var document struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	return response.Result().Cookies()[0], document.CSRFToken
}

func webRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, "https://product.example.test"+target, strings.NewReader(body))
	request.TLS = &tls.ConnectionState{}
	return request
}

type unusedFileStore struct{}

func (unusedFileStore) AuthorizeFileAccess(context.Context, string, product.ActorRef, string, string, string) error {
	return nil
}

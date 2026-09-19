package productweb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	if request.URL.Path == "/api/v1/capabilities" {
		_, _ = io.WriteString(writer, `{"contract_namespace":"urn:shell-echo:sandbox-runtime:product-v1alpha1","contract_version":"0.1.0","capabilities":[{"capability_id":"product.workspace","version":"1.0.0","readiness":"ready","protocol_profiles":["coding-shell-v1"],"max_session_seconds":0},{"capability_id":"product.terminal","version":"1.0.0","readiness":"ready","protocol_profiles":["product-terminal.v1"],"max_session_seconds":3600},{"capability_id":"product.files","version":"1.0.0","readiness":"ready","protocol_profiles":["guest-files.v1"],"max_session_seconds":0},{"capability_id":"product.browser","version":"1.0.0","readiness":"ready","protocol_profiles":["product-browser-live.v1"],"max_session_seconds":3600},{"capability_id":"product.desktop","version":"1.0.0","readiness":"ready","protocol_profiles":["product-desktop.v1"],"max_session_seconds":3600}],"max_page_size":200}`)
		return
	}
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
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "media-src 'self' blob:") || strings.Contains(csp, "'unsafe-inline'") || response.Header().Get("Strict-Transport-Security") == "" || response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers=%v", response.Header())
	}
	html := response.Body.String()
	for _, required := range []string{`<main id="main">`, `role="status"`, `aria-live="polite"`, `for="bearer"`, `type="module" src="/assets/app.js"`, `id="browser-panel"`, `id="browser-video"`, `id="recording-indicator"`, `id="desktop-panel"`, `id="desktop-video"`, `id="desktop-audio"`, `id="desktop-recording-indicator"`, `id="recordings-panel"`} {
		if !strings.Contains(html, required) {
			t.Fatalf("static UI missing %q", required)
		}
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "style=") {
		t.Fatal("static UI contains inline executable/style content")
	}
}

func TestUnifiedProductUIUsesGeneratedClientAndClosedPublicProfiles(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	document := string(script)
	for _, required := range []string{
		`import { callProduct }`, `getProductCapabilities`, `product-browser-live.v1`, `product-browser-control.v1`,
		`new RTCPeerConnection()`, `gatewayURL.origin !== location.origin`, `recording_consent_reference`,
		`listWorkspaceRecordings`, `/web/browser-transfers/uploads`, `crypto.subtle.digest`,
		`product-desktop.v1`, `product-desktop-control.v1`, `stream.configure`, `stream.resync`,
		`clipboard.read`, `clipboard.write`, `transfer.upload`, `transfer.download`, `/web/transfers/uploads`,
	} {
		if !strings.Contains(document, required) {
			t.Fatalf("unified Product UI missing %q", required)
		}
	}
	for _, forbidden := range []string{"localStorage", "sessionStorage", ".innerHTML", "provider_handoff", "object_reference"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("unified Product UI contains forbidden surface %q", forbidden)
		}
	}
}

func TestBrowserTransferBFFEnforcesSessionOriginCSRFAndStreamsAuthorizedBytes(t *testing.T) {
	server, _, _ := newWebServer(t, nil)
	transfers := &transferSpy{download: []byte("verified browser download")}
	server.transfers = transfers
	cookie, csrf := loginWebSession(t, server)
	payload := []byte("verified browser upload")
	digestValue := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(digestValue[:])
	target := "/web/transfers/uploads?workspace_id=wrk-1&expected_workspace_version=3&digest=" + digest + "&size_bytes=" + strconv.Itoa(len(payload))

	rejected := webRequest(http.MethodPost, target, string(payload))
	rejected.AddCookie(cookie)
	rejected.Header.Set("Origin", "https://product.example.test")
	rejected.Header.Set("Idempotency-Key", "upload-rejected")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, rejected)
	if response.Code != http.StatusForbidden || transfers.beginCalls != 0 {
		t.Fatalf("missing-CSRF upload status=%d calls=%d", response.Code, transfers.beginCalls)
	}

	upload := webRequest(http.MethodPost, target, string(payload))
	upload.AddCookie(cookie)
	upload.Header.Set("Origin", "https://product.example.test")
	upload.Header.Set("X-CSRF-Token", csrf)
	upload.Header.Set("Idempotency-Key", "upload-accepted")
	upload.Header.Set("Content-Type", "application/octet-stream")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, upload)
	if response.Code != http.StatusCreated || transfers.beginCalls != 1 || transfers.cancelled || !bytes.Equal(transfers.upload, payload) {
		t.Fatalf("upload status=%d spy=%#v body=%s", response.Code, transfers, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "object") || strings.Contains(response.Body.String(), "staging") {
		t.Fatalf("upload exposed private storage metadata: %s", response.Body.String())
	}

	download := webRequest(http.MethodGet, "/web/transfers/xfer-download", "")
	download.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, download)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), transfers.download) || response.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("download status=%d body=%q headers=%v", response.Code, response.Body.Bytes(), response.Header())
	}
	if transfers.tenantID != "tenant-1" || transfers.actor.ID != "actor-1" {
		t.Fatalf("transfer authority=%q %#v", transfers.tenantID, transfers.actor)
	}
}

type transferSpy struct {
	beginCalls int
	upload     []byte
	download   []byte
	cancelled  bool
	tenantID   string
	actor      product.ActorRef
}

func (s *transferSpy) BeginUpload(_ context.Context, tenantID string, actor product.ActorRef, workspaceID, key string, request product.BeginUploadRequest) (product.BlobTransfer, bool, error) {
	s.beginCalls++
	s.tenantID, s.actor = tenantID, actor
	return product.BlobTransfer{ID: "xfer-upload", WorkspaceID: workspaceID, Direction: "upload", Digest: request.Digest, SizeBytes: request.SizeBytes, State: "pending", Version: 1, ExpiresAt: time.Now().Add(time.Minute)}, false, nil
}

func (s *transferSpy) Append(_ context.Context, tenantID string, actor product.ActorRef, transferID string, offset int64, chunk []byte) (product.BlobTransfer, error) {
	s.tenantID, s.actor = tenantID, actor
	if transferID != "xfer-upload" || offset != int64(len(s.upload)) {
		return product.BlobTransfer{}, product.ErrVersionConflict
	}
	s.upload = append(s.upload, chunk...)
	digestValue := sha256.Sum256(s.upload)
	return product.BlobTransfer{ID: transferID, WorkspaceID: "wrk-1", Direction: "upload", Digest: "sha256:" + hex.EncodeToString(digestValue[:]), State: "transferring", SizeBytes: int64(len(s.upload)), CommittedBytes: int64(len(s.upload))}, nil
}

func (s *transferSpy) Complete(_ context.Context, tenantID string, actor product.ActorRef, transferID string) (product.BlobTransfer, error) {
	s.tenantID, s.actor = tenantID, actor
	digestValue := sha256.Sum256(s.upload)
	return product.BlobTransfer{ID: transferID, WorkspaceID: "wrk-1", Direction: "upload", Digest: "sha256:" + hex.EncodeToString(digestValue[:]), State: "complete", SizeBytes: int64(len(s.upload)), CommittedBytes: int64(len(s.upload)), ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (s *transferSpy) Cancel(context.Context, string, product.ActorRef, string) error {
	s.cancelled = true
	return nil
}

func (s *transferSpy) ReadDownload(_ context.Context, tenantID string, actor product.ActorRef, transferID string, offset int64, limit int) ([]byte, bool, error) {
	s.tenantID, s.actor = tenantID, actor
	if transferID != "xfer-download" || offset < 0 || offset > int64(len(s.download)) {
		return nil, false, product.ErrNotFound
	}
	end := min(len(s.download), int(offset)+limit)
	return append([]byte(nil), s.download[int(offset):end]...), end == len(s.download), nil
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

// Package productweb provides the browser-facing Product BFF and embedded UI.
// Browser sessions contain only opaque, Secure, HttpOnly cookies; Product bearer
// credentials remain encrypted in the server-side session store.
package productweb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const (
	sessionCookieName = "__Host-product_session"
	maxLoginBodyBytes = 1024
)

//go:embed assets/*
var assets embed.FS

//go:generate go run ../internal/cmd/productweb-client-gen -openapi ../product-contract/openapi/sandbox-runtime-product-v1alpha1.yaml -output assets/client.generated.js

type Options struct {
	ProductAPI           http.Handler
	Authenticator        productapi.Authenticator
	Files                *product.FileService
	SessionEncryptionKey []byte
	PublicOrigin         string
	SessionTTL           time.Duration
	IdleTTL              time.Duration
	MaxSessions          int
	Clock                func() time.Time
	Random               io.Reader
}

type Server struct {
	productAPI    http.Handler
	authenticator productapi.Authenticator
	files         *product.FileService
	origin        string
	clock         func() time.Time
	sessionTTL    time.Duration
	random        io.Reader
	aead          cipher.AEAD
	sessions      *sessionStore
	static        http.Handler
}

type browserSession struct {
	principal      productapi.Principal
	encryptedToken []byte
	csrfDigest     [32]byte
	createdAt      time.Time
	lastSeenAt     time.Time
	expiresAt      time.Time
}

type sessionStore struct {
	mu      sync.Mutex
	records map[[32]byte]browserSession
	maximum int
	idleTTL time.Duration
	clock   func() time.Time
}

func New(options Options) (*Server, error) {
	if options.ProductAPI == nil || productapi.IsNilAuthenticator(options.Authenticator) || len(options.SessionEncryptionKey) != 32 {
		return nil, product.ErrInvalid
	}
	parsedOrigin, err := url.Parse(options.PublicOrigin)
	if err != nil || parsedOrigin.Scheme != "https" || parsedOrigin.Host == "" || parsedOrigin.User != nil || parsedOrigin.RawQuery != "" || parsedOrigin.Fragment != "" || (parsedOrigin.Path != "" && parsedOrigin.Path != "/") {
		return nil, product.ErrInvalid
	}
	sessionTTL := options.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 8 * time.Hour
	}
	idleTTL := options.IdleTTL
	if idleTTL == 0 {
		idleTTL = 30 * time.Minute
	}
	maximum := options.MaxSessions
	if maximum == 0 {
		maximum = 10000
	}
	if sessionTTL < time.Minute || sessionTTL > 24*time.Hour || idleTTL < time.Minute || idleTTL > sessionTTL || maximum < 1 || maximum > 100000 {
		return nil, product.ErrInvalid
	}
	block, err := aes.NewCipher(append([]byte(nil), options.SessionEncryptionKey...))
	if err != nil {
		return nil, product.ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, product.ErrInvalid
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	randomSource := options.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	staticFS, err := fs.Sub(assets, "assets")
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	return &Server{
		productAPI: options.ProductAPI, authenticator: options.Authenticator, files: options.Files,
		origin: strings.TrimSuffix(options.PublicOrigin, "/"), clock: clock, random: randomSource,
		sessionTTL: sessionTTL,
		aead:       aead, sessions: &sessionStore{records: make(map[[32]byte]browserSession), maximum: maximum, idleTTL: idleTTL, clock: clock},
		static: http.FileServer(http.FS(staticFS)),
	}, nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	securityHeaders(writer.Header(), request.TLS != nil)
	if s == nil || request == nil {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	switch {
	case request.URL.Path == "/web/session":
		s.sessionRoute(writer, request)
	case strings.HasPrefix(request.URL.Path, "/web/api/"):
		s.proxyProductAPI(writer, request)
	case strings.HasPrefix(request.URL.Path, "/web/data/"):
		s.fileRoute(writer, request)
	case request.Method == http.MethodGet && (request.URL.Path == "/" || strings.HasPrefix(request.URL.Path, "/assets/")):
		if request.URL.Path == "/" {
			document, err := assets.ReadFile("assets/index.html")
			if err != nil {
				writeWebError(writer, http.StatusServiceUnavailable, "WEB_ASSET_UNAVAILABLE", "web asset unavailable")
				return
			}
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(document)
			return
		}
		request = request.Clone(request.Context())
		request.URL.Path = strings.TrimPrefix(request.URL.Path, "/assets")
		writer.Header().Set("Cache-Control", "no-store")
		s.static.ServeHTTP(writer, request)
	default:
		writeWebError(writer, http.StatusNotFound, "WEB_NOT_FOUND", "resource not found")
	}
}

func securityHeaders(header http.Header, tls bool) {
	header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' wss:; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	if tls {
		header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func (s *Server) sessionRoute(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		if !s.exactOrigin(request) || request.ContentLength > maxLoginBodyBytes {
			writeWebError(writer, http.StatusForbidden, "WEB_ORIGIN_REJECTED", "request origin is not allowed")
			return
		}
		token, ok := bearer(request.Header.Values("Authorization"))
		request.Header.Del("Authorization")
		if !ok {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			writeWebError(writer, http.StatusUnauthorized, "WEB_UNAUTHENTICATED", "authentication is required")
			return
		}
		principal, err := s.authenticator.Authenticate(request.Context(), token)
		if err != nil {
			writeWebError(writer, http.StatusUnauthorized, "WEB_UNAUTHENTICATED", "authentication is required")
			return
		}
		s.createSession(writer, token, principal)
		token = ""
	case http.MethodGet:
		sessionID, session, ok := s.requireSession(writer, request)
		if !ok || !s.safeFetch(writer, request) {
			return
		}
		csrf, err := randomToken(s.random)
		if err != nil {
			writeWebError(writer, http.StatusServiceUnavailable, "WEB_SESSION_UNAVAILABLE", "session service unavailable")
			return
		}
		session.csrfDigest = sha256.Sum256([]byte(csrf))
		s.sessions.replace(sessionID, session)
		writeWebJSON(writer, http.StatusOK, sessionDocument(session.principal, csrf, session.expiresAt))
	case http.MethodDelete:
		sessionID, session, ok := s.requireSession(writer, request)
		if !ok || !s.authorizeMutation(writer, request, session) {
			return
		}
		s.sessions.delete(sessionID)
		http.SetCookie(writer, expiredSessionCookie())
		writer.WriteHeader(http.StatusNoContent)
	default:
		writer.Header().Set("Allow", "GET, POST, DELETE")
		writeWebError(writer, http.StatusMethodNotAllowed, "WEB_METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (s *Server) createSession(writer http.ResponseWriter, token string, principal productapi.Principal) {
	sessionID, err := randomToken(s.random)
	if err != nil {
		writeWebError(writer, http.StatusServiceUnavailable, "WEB_SESSION_UNAVAILABLE", "session service unavailable")
		return
	}
	csrf, err := randomToken(s.random)
	if err != nil {
		writeWebError(writer, http.StatusServiceUnavailable, "WEB_SESSION_UNAVAILABLE", "session service unavailable")
		return
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		writeWebError(writer, http.StatusServiceUnavailable, "WEB_SESSION_UNAVAILABLE", "session service unavailable")
		return
	}
	ciphertext := s.aead.Seal(nonce, nonce, []byte(token), []byte(s.origin))
	now := s.clock().UTC()
	session := browserSession{principal: principal, encryptedToken: ciphertext, csrfDigest: sha256.Sum256([]byte(csrf)), createdAt: now, lastSeenAt: now, expiresAt: now.Add(s.sessionTTL)}
	if !s.sessions.create(sessionID, session) {
		writeWebError(writer, http.StatusServiceUnavailable, "WEB_SESSION_CAPACITY", "session capacity is exhausted")
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Value: sessionID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: session.expiresAt, MaxAge: int(s.sessionTTL.Seconds())})
	writeWebJSON(writer, http.StatusCreated, sessionDocument(principal, csrf, session.expiresAt))
}

func sessionDocument(principal productapi.Principal, csrf string, expires time.Time) map[string]any {
	return map[string]any{"csrf_token": csrf, "expires_at": expires.UTC().Format(time.RFC3339Nano), "principal": map[string]string{"tenant_id": principal.TenantID, "actor_type": string(principal.Actor.Type), "actor_id": principal.Actor.ID, "role": string(principal.Role)}}
}

func (s *Server) proxyProductAPI(writer http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireSession(writer, request)
	if !ok || !s.safeFetch(writer, request) {
		return
	}
	if isMutation(request.Method) && !s.authorizeMutation(writer, request, session) {
		return
	}
	if len(request.Header.Values("Authorization")) != 0 {
		writeWebError(writer, http.StatusBadRequest, "WEB_INVALID_REQUEST", "authorization header is not accepted")
		return
	}
	token, err := s.decryptToken(session.encryptedToken)
	if err != nil {
		writeWebError(writer, http.StatusUnauthorized, "WEB_SESSION_INVALID", "session is invalid")
		return
	}
	proxied := request.Clone(request.Context())
	proxied.URL.Path = strings.TrimPrefix(request.URL.Path, "/web")
	proxied.RequestURI = ""
	proxied.Header = request.Header.Clone()
	proxied.Header.Del("Cookie")
	proxied.Header.Del("X-CSRF-Token")
	proxied.Header.Set("Authorization", "Bearer "+token)
	token = ""
	s.productAPI.ServeHTTP(writer, proxied)
}

func (s *Server) fileRoute(writer http.ResponseWriter, request *http.Request) {
	if s.files == nil {
		writeWebError(writer, http.StatusServiceUnavailable, "WEB_FILES_UNAVAILABLE", "file service is unavailable")
		return
	}
	_, session, ok := s.requireSession(writer, request)
	if !ok || !s.safeFetch(writer, request) {
		return
	}
	if isMutation(request.Method) && !s.authorizeMutation(writer, request, session) {
		return
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) < 7 || len(parts) > 8 || parts[0] != "web" || parts[1] != "data" || parts[2] != "workspaces" || parts[4] != "slots" || parts[6] != "files" {
		writeWebError(writer, http.StatusNotFound, "WEB_NOT_FOUND", "resource not found")
		return
	}
	workspaceID, slotKey := parts[3], parts[5]
	query := request.URL.Query()
	guestPath := query.Get("path")
	ctx := request.Context()
	var result any
	var err error
	switch {
	case request.Method == http.MethodGet && len(parts) == 7:
		limit, valid := boundedInt(query.Get("limit"), 50, 1, product.MaxFilePageSize)
		if !valid || !onlyQuery(query, "path", "after", "limit") {
			err = product.ErrInvalid
			break
		}
		var page product.FilePage
		page, err = s.files.List(ctx, session.principal.TenantID, session.principal.Actor, workspaceID, slotKey, guestPath, query.Get("after"), limit)
		result = projectFilePage(page)
	case request.Method == http.MethodGet && len(parts) == 8 && parts[7] == "stat":
		if !onlyQuery(query, "path") {
			err = product.ErrInvalid
			break
		}
		var entry product.FileEntry
		entry, err = s.files.Stat(ctx, session.principal.TenantID, session.principal.Actor, workspaceID, slotKey, guestPath)
		result = projectFileEntry(entry)
	case request.Method == http.MethodGet && len(parts) == 8 && parts[7] == "changes":
		after, validAfter := boundedInt64(query.Get("after"), 0, 0)
		limit, validLimit := boundedInt(query.Get("limit"), 50, 1, product.MaxFilePageSize)
		if !validAfter || !validLimit || !onlyQuery(query, "after", "limit") {
			err = product.ErrInvalid
			break
		}
		var changes []product.FileChange
		changes, err = s.files.Changes(ctx, session.principal.TenantID, session.principal.Actor, workspaceID, slotKey, after, limit)
		result = projectFileChanges(changes)
	case request.Method == http.MethodPost && len(parts) == 8 && parts[7] == "refresh":
		if !onlyQuery(query, "path") {
			err = product.ErrInvalid
			break
		}
		var changes []product.FileChange
		changes, err = s.files.Refresh(ctx, session.principal.TenantID, session.principal.Actor, workspaceID, slotKey, guestPath)
		result = projectFileChanges(changes)
	default:
		writeWebError(writer, http.StatusNotFound, "WEB_NOT_FOUND", "resource not found")
		return
	}
	if err != nil {
		writeFileError(writer, err)
		return
	}
	writeWebJSON(writer, http.StatusOK, result)
}

func (s *Server) requireSession(writer http.ResponseWriter, request *http.Request) (string, browserSession, bool) {
	sessionID, ok := singleCookie(request, sessionCookieName)
	if !ok {
		writeWebError(writer, http.StatusUnauthorized, "WEB_UNAUTHENTICATED", "browser session is required")
		return "", browserSession{}, false
	}
	session, ok := s.sessions.get(sessionID)
	if !ok {
		http.SetCookie(writer, expiredSessionCookie())
		writeWebError(writer, http.StatusUnauthorized, "WEB_SESSION_EXPIRED", "browser session expired")
		return "", browserSession{}, false
	}
	return sessionID, session, true
}

func (s *Server) exactOrigin(request *http.Request) bool {
	values := request.Header.Values("Origin")
	return len(values) == 1 && values[0] == s.origin
}

func (s *Server) safeFetch(writer http.ResponseWriter, request *http.Request) bool {
	if origins := request.Header.Values("Origin"); len(origins) > 1 || (len(origins) == 1 && origins[0] != s.origin) {
		writeWebError(writer, http.StatusForbidden, "WEB_ORIGIN_REJECTED", "request origin is not allowed")
		return false
	}
	if request.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeWebError(writer, http.StatusForbidden, "WEB_ORIGIN_REJECTED", "cross-site request is not allowed")
		return false
	}
	return true
}

func (s *Server) authorizeMutation(writer http.ResponseWriter, request *http.Request, session browserSession) bool {
	if !s.exactOrigin(request) {
		writeWebError(writer, http.StatusForbidden, "WEB_ORIGIN_REJECTED", "request origin is not allowed")
		return false
	}
	values := request.Header.Values("X-CSRF-Token")
	if len(values) != 1 {
		writeWebError(writer, http.StatusForbidden, "WEB_CSRF_REJECTED", "csrf token is invalid")
		return false
	}
	digest := sha256.Sum256([]byte(values[0]))
	if subtle.ConstantTimeCompare(digest[:], session.csrfDigest[:]) != 1 {
		writeWebError(writer, http.StatusForbidden, "WEB_CSRF_REJECTED", "csrf token is invalid")
		return false
	}
	return true
}

func (s *Server) decryptToken(ciphertext []byte) (string, error) {
	if len(ciphertext) <= s.aead.NonceSize() {
		return "", product.ErrInvalid
	}
	nonce := ciphertext[:s.aead.NonceSize()]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext[s.aead.NonceSize():], []byte(s.origin))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *sessionStore) create(sessionID string, session browserSession) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	if len(s.records) >= s.maximum {
		return false
	}
	s.records[sha256.Sum256([]byte(sessionID))] = session
	return true
}

func (s *sessionStore) get(sessionID string) (browserSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(sessionID))
	session, ok := s.records[key]
	if !ok {
		return browserSession{}, false
	}
	now := s.clock().UTC()
	if !now.Before(session.expiresAt) || now.Sub(session.lastSeenAt) > s.idleTTL {
		delete(s.records, key)
		return browserSession{}, false
	}
	session.lastSeenAt = now
	s.records[key] = session
	return session, true
}

func (s *sessionStore) replace(sessionID string, session browserSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(sessionID))
	if _, ok := s.records[key]; ok {
		s.records[key] = session
	}
}

func (s *sessionStore) delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, sha256.Sum256([]byte(sessionID)))
}

func (s *sessionStore) purgeExpiredLocked() {
	now := s.clock().UTC()
	for key, session := range s.records {
		if !now.Before(session.expiresAt) || now.Sub(session.lastSeenAt) > s.idleTTL {
			delete(s.records, key)
		}
	}
}

func bearer(values []string) (string, bool) {
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	return token, token != "" && len(token) <= 4096 && !strings.ContainsAny(token, " \t\r\n,")
}

func randomToken(source io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func singleCookie(request *http.Request, name string) (string, bool) {
	var value string
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == name {
			value = cookie.Value
			count++
		}
	}
	return value, count == 1 && len(value) >= 32 && len(value) <= 128 && !strings.ContainsAny(value, " \t\r\n,;")
}

func expiredSessionCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)}
}

func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func onlyQuery(values url.Values, allowed ...string) bool {
	set := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		set[name] = true
	}
	for name, entries := range values {
		if !set[name] || len(entries) != 1 {
			return false
		}
	}
	return true
}

func boundedInt(value string, fallback, minimum, maximum int) (int, bool) {
	if value == "" {
		return fallback, true
	}
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && parsed >= minimum && parsed <= maximum
}

func boundedInt64(value string, fallback, minimum int64) (int64, bool) {
	if value == "" {
		return fallback, true
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed >= minimum
}

func projectFileEntry(entry product.FileEntry) map[string]any {
	return map[string]any{"path": entry.Path, "name": entry.Name, "type": entry.Type, "revision": entry.Revision, "mode": entry.Mode, "size_bytes": entry.SizeBytes, "modified_at": entry.ModifiedAt.UTC().Format(time.RFC3339Nano)}
}

func projectFilePage(page product.FilePage) map[string]any {
	items := make([]map[string]any, 0, len(page.Items))
	for _, entry := range page.Items {
		items = append(items, projectFileEntry(entry))
	}
	return map[string]any{"items": items, "next_after": page.NextAfter}
}

func projectFileChanges(changes []product.FileChange) map[string]any {
	items := make([]map[string]any, 0, len(changes))
	for _, change := range changes {
		items = append(items, map[string]any{"sequence": change.Sequence, "path": change.Path, "previous_path": change.PreviousPath, "type": change.Type, "revision": change.Revision, "occurred_at": change.OccurredAt.UTC().Format(time.RFC3339Nano)})
	}
	return map[string]any{"items": items}
}

func writeFileError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, product.ErrInvalid):
		writeWebError(writer, http.StatusBadRequest, "WEB_INVALID_REQUEST", "invalid request")
	case errors.Is(err, product.ErrNotFound):
		writeWebError(writer, http.StatusNotFound, "WEB_NOT_FOUND", "resource not found")
	case errors.Is(err, product.ErrForbidden):
		writeWebError(writer, http.StatusForbidden, "WEB_FORBIDDEN", "action is forbidden")
	case errors.Is(err, product.ErrCursorExpired):
		writeWebError(writer, http.StatusGone, "WEB_CURSOR_EXPIRED", "change cursor expired")
	default:
		writeWebError(writer, http.StatusServiceUnavailable, "WEB_DEPENDENCY_UNAVAILABLE", "dependency unavailable")
	}
}

func writeWebError(writer http.ResponseWriter, status int, code, message string) {
	writeWebJSON(writer, status, map[string]any{"code": code, "message": message})
}

func writeWebJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func init() {
	_ = mime.AddExtensionType(".js", "text/javascript; charset=utf-8")
}

var _ http.Handler = (*Server)(nil)

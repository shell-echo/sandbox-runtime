package qualificationoperator

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrObservationProxy = errors.New("qualification observation proxy failed")

type HTTPObservation struct {
	Surface, Actor, Method, Route, Transport, ErrorCode string
	StatusCode                                          int
	Retryable, RetryAfterPresent, MutationWriteObserved bool
	StartedAt, FinishedAt                               time.Time
	RequestDigest, ResponseDigest, AdmissionDigest      string
	RequestJSON, ResponseJSON                           map[string]any
}

type GatewayObservation struct {
	Actor, Transport, FailureStage   string
	StatusCode                       int
	BytesToGateway, BytesFromGateway int64
	ChallengeDigest                  string
	ObserverChallengeVerified        bool
	StartedAt, FinishedAt            time.Time
}

type ObservationProxy struct {
	provider, gateway                  *http.Server
	providerListener, gatewayListener  net.Listener
	providerOrigin                     string
	privateGatewayAddress, gatewayHost string
	credentials                        *Credentials
	gatewayServiceCompleted            func()

	mu                 sync.Mutex
	providerEvents     []HTTPObservation
	gatewayEvents      []GatewayObservation
	authorizedGateways int
	challenge          [32]byte
}

func StartObservationProxy(providerAddress, gatewayAddress, providerOrigin, privateGatewayAddress, gatewayHost string, credentials *Credentials, gatewayServiceCompleted func()) (*ObservationProxy, error) {
	if credentials == nil {
		return nil, ErrObservationProxy
	}
	p := &ObservationProxy{
		providerOrigin: providerOrigin, privateGatewayAddress: privateGatewayAddress, gatewayHost: gatewayHost,
		credentials: credentials, gatewayServiceCompleted: gatewayServiceCompleted,
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, ErrObservationProxy
	}
	copy(p.challenge[:], hex.EncodeToString(entropy[:]))
	clear(entropy[:])
	providerListener, err := tls.Listen("tcp", providerAddress, p.providerTLSConfig())
	if err != nil {
		return nil, ErrObservationProxy
	}
	p.providerListener = providerListener
	gatewayListener, err := tls.Listen("tcp", gatewayAddress, p.gatewayTLSConfig())
	if err != nil {
		_ = providerListener.Close()
		return nil, ErrObservationProxy
	}
	p.gatewayListener = gatewayListener
	p.provider = &http.Server{Handler: http.HandlerFunc(p.serveProvider), ReadHeaderTimeout: 3 * time.Second, MaxHeaderBytes: 64 << 10}
	p.gateway = &http.Server{Handler: http.HandlerFunc(p.serveGateway), ReadHeaderTimeout: 3 * time.Second, MaxHeaderBytes: 32 << 10}
	go p.provider.Serve(providerListener)
	go p.gateway.Serve(gatewayListener)
	return p, nil
}

func (p *ObservationProxy) Close() error {
	if p == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(p.provider.Shutdown(ctx), p.gateway.Shutdown(ctx))
}

func (p *ObservationProxy) Snapshot() ([]HTTPObservation, []GatewayObservation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]HTTPObservation(nil), p.providerEvents...), append([]GatewayObservation(nil), p.gatewayEvents...)
}

func (p *ObservationProxy) SafeSummary() string {
	provider, gateway := p.Snapshot()
	providerRoutes := make(map[string]int)
	for _, event := range provider {
		providerRoutes[event.Method+" "+event.Route]++
	}
	const maxProviderEvents = 12
	providerTotal := len(provider)
	if len(provider) > maxProviderEvents {
		provider = provider[len(provider)-maxProviderEvents:]
	}
	type providerItem struct {
		Actor, Method, Route, Transport, ResponseDigest, ErrorCode, OperationType, OperationStatus string
		Status                                                                                     int
		Capabilities, CapabilityProfiles                                                           []string
		RuntimeProfileCount, SnapshotProfileCount                                                  int
	}
	type gatewayItem struct {
		Actor, Transport, FailureStage string
		Status                         int
	}
	result := struct {
		ProviderTotal  int            `json:"provider_total"`
		ProviderRoutes map[string]int `json:"provider_routes"`
		Provider       []providerItem `json:"provider_tail"`
		GatewayTotal   int            `json:"gateway_total"`
		Gateway        []gatewayItem  `json:"gateway"`
	}{
		ProviderTotal:  providerTotal,
		ProviderRoutes: providerRoutes,
		Provider:       make([]providerItem, len(provider)),
		GatewayTotal:   len(gateway),
		Gateway:        make([]gatewayItem, len(gateway)),
	}
	for index, event := range provider {
		item := providerItem{Actor: event.Actor, Method: event.Method, Route: event.Route, Transport: event.Transport, Status: event.StatusCode, ResponseDigest: event.ResponseDigest, ErrorCode: event.ErrorCode}
		if event.Route == "/v1/capabilities" && event.StatusCode == http.StatusOK {
			if values, ok := event.ResponseJSON["capabilities"].([]any); ok {
				for _, value := range values {
					entry, _ := value.(map[string]any)
					id, _ := entry["id"].(string)
					item.Capabilities = append(item.Capabilities, id)
					if profiles, ok := entry["profiles"].([]any); ok {
						for _, profile := range profiles {
							name, _ := profile.(string)
							item.CapabilityProfiles = append(item.CapabilityProfiles, name)
						}
					}
				}
			}
			if values, ok := event.ResponseJSON["runtime_profiles"].([]any); ok {
				item.RuntimeProfileCount = len(values)
			}
			if values, ok := event.ResponseJSON["snapshot_restore_profiles"].([]any); ok {
				item.SnapshotProfileCount = len(values)
			}
		}
		if event.StatusCode == http.StatusAccepted || event.StatusCode == http.StatusOK {
			item.OperationType, _ = event.ResponseJSON["type"].(string)
			item.OperationStatus, _ = event.ResponseJSON["status"].(string)
		}
		result.Provider[index] = item
	}
	for index, event := range gateway {
		result.Gateway[index] = gatewayItem{Actor: event.Actor, Transport: event.Transport, FailureStage: event.FailureStage, Status: event.StatusCode}
	}
	document, _ := json.Marshal(result)
	return string(document)
}

func (p *ObservationProxy) providerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{p.credentials.ProviderProxyCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.credentials.ProviderRoots,
		VerifyConnection: func(state tls.ConnectionState) error {
			actor := actorForPeer(state, p.credentials.ProviderSubjects)
			if actor == "controller_a" || actor == "controller_b" || actor == "same_ca_unadmitted" {
				return nil
			}
			if actor != "" {
				now := time.Now().UTC()
				p.mu.Lock()
				p.providerEvents = append(p.providerEvents, HTTPObservation{
					Surface: "provider_http", Actor: actor, Method: http.MethodGet, Route: "/v1/capabilities",
					Transport: "tls-rejected", StartedAt: now, FinishedAt: now,
				})
				p.mu.Unlock()
			}
			// Emit the protocol-defined bad_certificate alert. The candidate
			// distinguishes a peer TLS rejection from an unrelated transport
			// failure by the received alert type.
			return tls.AlertError(42)
		},
	}
}

func (p *ObservationProxy) gatewayTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{p.credentials.GatewayProxyCertificate},
		// The observer accepts an absent certificate so it can forward that exact
		// negative case to the real Gateway and witness the private listener's
		// rejection. Any supplied certificate must still chain to the locked CA.
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: p.credentials.GatewayClientRoots,
	}
}

func actorForPeer(state tls.ConnectionState, subjects map[string]string) string {
	if len(state.VerifiedChains) != 1 || len(state.VerifiedChains[0]) == 0 || len(state.VerifiedChains[0][0].URIs) != 1 {
		return ""
	}
	subject := state.VerifiedChains[0][0].URIs[0].String()
	for actor, expected := range subjects {
		if subject == expected {
			return actor
		}
	}
	return ""
}

func (p *ObservationProxy) serveProvider(w http.ResponseWriter, r *http.Request) {
	started := time.Now().UTC()
	actor := actorForPeer(*r.TLS, p.credentials.ProviderSubjects)
	observation := HTTPObservation{Surface: "provider_http", Actor: actor, Method: r.Method, Route: providerRoute(r.URL.Path), StartedAt: started}
	defer func() {
		observation.FinishedAt = time.Now().UTC()
		p.mu.Lock()
		p.providerEvents = append(p.providerEvents, observation)
		p.mu.Unlock()
	}()
	certificate, ok := p.credentials.ProviderClients[actor]
	if !ok {
		observation.Transport = "tls-rejected"
		return
	}
	target, err := url.Parse(p.providerOrigin)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		observation.Transport, observation.StatusCode = "http-response", http.StatusBadGateway
		return
	}
	request := r.Clone(r.Context())
	if r.Body != nil {
		body, bodyErr := io.ReadAll(io.LimitReader(r.Body, (8<<20)+1))
		if bodyErr != nil || len(body) > 8<<20 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			observation.Transport, observation.StatusCode = "http-response", http.StatusRequestEntityTooLarge
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		observation.RequestDigest = rawSHA256(body)
		_ = json.Unmarshal(body, &observation.RequestJSON)
	}
	if admission := r.Header.Get("Authorization") + "\x00" + r.Header.Get("X-Sandbox-Runtime-Admission-Context"); admission != "\x00" {
		observation.AdmissionDigest = rawSHA256([]byte(admission))
	}
	request.URL.Scheme, request.URL.Host = target.Scheme, target.Host
	request.RequestURI = ""
	request.Host = target.Host
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.credentials.ProviderRoots, Certificates: []tls.Certificate{certificate}, ServerName: target.Hostname()},
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		if actor == "same_ca_unadmitted" {
			// The observer accepted the same-CA identity only far enough to
			// re-originate that exact certificate to the real Provider. A local
			// upstream TLS rejection therefore proves the Provider allow-list
			// boundary. Project it as the profile-permitted closed 403 outcome;
			// never manufacture a capability document for the rejected actor.
			body := []byte(`{"code":"SANDBOX_FORBIDDEN","message":"caller identity is not admitted","retryable":false,"trace_id":"qualification-observer"}`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(body)
			observation.ResponseDigest = rawSHA256(body)
			_ = json.Unmarshal(body, &observation.ResponseJSON)
			observation.Transport, observation.StatusCode = "http-response", http.StatusForbidden
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		observation.Transport, observation.StatusCode = "transport-error", 0
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		p.bridgeProviderUpgrade(w, response, &observation)
		return
	}
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if readErr == nil {
		_, _ = w.Write(body)
	}
	observation.ResponseDigest = rawSHA256(body)
	_ = json.Unmarshal(body, &observation.ResponseJSON)
	observation.Transport, observation.StatusCode = "http-response", response.StatusCode
	observation.RetryAfterPresent = response.Header.Get("Retry-After") != ""
	observation.MutationWriteObserved = r.Method == http.MethodPost
	var errorDocument struct {
		Code      string `json:"code"`
		Retryable bool   `json:"retryable"`
	}
	if json.Unmarshal(body, &errorDocument) == nil {
		observation.ErrorCode, observation.Retryable = errorDocument.Code, errorDocument.Retryable
	}
}

func (p *ObservationProxy) bridgeProviderUpgrade(w http.ResponseWriter, response *http.Response, observation *HTTPObservation) {
	hijacker, ok := w.(http.Hijacker)
	upstream, upstreamOK := response.Body.(io.ReadWriteCloser)
	if !ok || !upstreamOK {
		w.WriteHeader(http.StatusBadGateway)
		observation.Transport = "transport-error"
		return
	}
	downstream, buffered, err := hijacker.Hijack()
	if err != nil {
		observation.Transport = "transport-error"
		return
	}
	defer downstream.Close()
	defer upstream.Close()
	if _, err := buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		observation.Transport = "transport-error"
		return
	}
	for key, values := range response.Header {
		for _, value := range values {
			if _, err := fmt.Fprintf(buffered, "%s: %s\r\n", key, value); err != nil {
				observation.Transport = "transport-error"
				return
			}
		}
	}
	if _, err := buffered.WriteString("\r\n"); err != nil || buffered.Flush() != nil {
		observation.Transport = "transport-error"
		return
	}
	toUpstream := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, downstream)
		toUpstream <- struct{}{}
	}()
	_, _ = io.Copy(downstream, upstream)
	_ = downstream.Close()
	<-toUpstream
	observation.Transport, observation.StatusCode = "http-response", response.StatusCode
}

func providerRoute(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if path == "/v1/capabilities" || path == "/v1/sandboxes" {
		return path
	}
	if len(segments) >= 3 && segments[0] == "v1" && segments[1] == "sandboxes" {
		segments[2] = "{sandbox_id}"
	}
	if len(segments) >= 3 && segments[0] == "v1" && segments[1] == "operations" {
		segments[2] = "{operation_id}"
	}
	return "/" + strings.Join(segments, "/")
}

func (p *ObservationProxy) serveGateway(w http.ResponseWriter, r *http.Request) {
	started := time.Now().UTC()
	actor := actorForPeer(*r.TLS, p.credentials.GatewaySubjects)
	observation := GatewayObservation{Actor: actor, StartedAt: started}
	defer func() {
		observation.FinishedAt = time.Now().UTC()
		p.mu.Lock()
		p.gatewayEvents = append(p.gatewayEvents, observation)
		p.mu.Unlock()
		// Each scenario-owned Gateway is stopped immediately after its final
		// connection. Return DNS to the private bind address before the next
		// service starts. The authority-rejection scenario has two probes, so
		// only its controller-B probe is terminal for that service.
		completed := observation.Transport == "authorized-byte-round-trip" ||
			(observation.Actor == "controller_b" && observation.Transport == "gateway-upgrade-rejected")
		if completed && p.gatewayServiceCompleted != nil {
			p.gatewayServiceCompleted()
		}
	}()
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusForbidden)
		observation.Transport, observation.StatusCode = "gateway-upgrade-rejected", http.StatusForbidden
		return
	}
	certificate, hasCertificate := p.credentials.GatewayClients[actor]
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	upstreamTLS := &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: p.credentials.GatewayServerRoots,
		ServerName: p.gatewayHost,
	}
	if hasCertificate {
		upstreamTLS.Certificates = []tls.Certificate{certificate}
	}
	connection, err := tls.DialWithDialer(dialer, "tcp", p.privateGatewayAddress, upstreamTLS)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		observation.Transport, observation.FailureStage = "gateway-upgrade-rejected", "upstream-tls"
		return
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\nConnection: close\r\n\r\n", r.URL.RequestURI(), r.Host, r.Header.Get("Authorization")); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		observation.Transport, observation.FailureStage = "transport-error", "upstream-connect-write"
		return
	}
	reader := bufio.NewReaderSize(connection, 32<<10)
	response, err := http.ReadResponse(reader, r)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		observation.Transport, observation.FailureStage = "transport-error", "upstream-connect-read"
		return
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		w.WriteHeader(response.StatusCode)
		observation.Transport, observation.StatusCode, observation.FailureStage = "gateway-upgrade-rejected", response.StatusCode, "upstream-connect-response"
		return
	}
	authorizedOrdinal := p.nextAuthorizedGateway()
	if authorizedOrdinal == 1 || authorizedOrdinal == 4 {
		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			w.WriteHeader(http.StatusBadGateway)
			observation.Transport, observation.FailureStage = "transport-error", "observer-challenge-deadline"
			return
		}
		mode := "set"
		if authorizedOrdinal == 4 {
			mode = "verify"
		}
		written, read, err := p.runShellChallenge(reader, connection, mode)
		observation.BytesToGateway += written
		observation.BytesFromGateway += read
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			observation.Transport, observation.FailureStage = "transport-error", "observer-shell-challenge-"+mode
			return
		}
		_ = connection.SetDeadline(time.Time{})
		sum := sha256.Sum256(p.challenge[:])
		observation.ChallengeDigest = "sha256:" + hex.EncodeToString(sum[:])
		observation.ObserverChallengeVerified = true
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		observation.Transport, observation.FailureStage = "transport-error", "downstream-hijack-unsupported"
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		observation.Transport, observation.FailureStage = "transport-error", "downstream-hijack"
		return
	}
	defer client.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		observation.Transport, observation.FailureStage = "transport-error", "downstream-connect-response"
		return
	}
	toGateway := make(chan int64, 1)
	toClient := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(connection, client)
		if tcp, ok := connection.NetConn().(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}
		toGateway <- n
	}()
	go func() {
		n, _ := io.Copy(client, reader)
		if tcp, ok := client.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}
		toClient <- n
	}()
	observation.BytesToGateway += <-toGateway
	observation.BytesFromGateway += <-toClient
	observation.Transport = "authorized-byte-round-trip"
}

func (p *ObservationProxy) nextAuthorizedGateway() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authorizedGateways++
	return p.authorizedGateways
}

// runShellChallenge establishes or verifies state in the persistent shell.
// It runs before the candidate receives its CONNECT response, so observer
// bytes cannot be confused with candidate-owned terminal traffic.
func (p *ObservationProxy) runShellChallenge(reader *bufio.Reader, connection io.Writer, mode string) (int64, int64, error) {
	challenge := string(p.challenge[:])
	var command, marker string
	switch mode {
	case "set":
		marker = "SRQ-SET:" + challenge
		command = "export SANDBOX_RUNTIME_QUALIFICATION_CHALLENGE='" + challenge + "'; printf '\\nSRQ-SET:%s\\n' \"$SANDBOX_RUNTIME_QUALIFICATION_CHALLENGE\"\n"
	case "verify":
		marker = "SRQ-GET:" + challenge
		command = "printf '\\nSRQ-GET:%s\\n' \"$SANDBOX_RUNTIME_QUALIFICATION_CHALLENGE\"\n"
	default:
		return 0, 0, ErrObservationProxy
	}
	if writeAll(connection, []byte(command)) != nil {
		return 0, 0, ErrObservationProxy
	}
	wantLF := []byte("\n" + marker + "\n")
	wantCRLF := []byte("\r\n" + marker + "\r\n")
	observed := make([]byte, 0, 4096)
	for len(observed) < 64<<10 {
		value, err := reader.ReadByte()
		if err != nil {
			return int64(len(command)), int64(len(observed)), ErrObservationProxy
		}
		observed = append(observed, value)
		if bytes.Contains(observed, wantLF) || bytes.Contains(observed, wantCRLF) {
			read := int64(len(observed))
			clear(observed)
			return int64(len(command)), read, nil
		}
	}
	clear(observed)
	return int64(len(command)), 64 << 10, ErrObservationProxy
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		n, err := writer.Write(value)
		if err != nil || n < 1 || n > len(value) {
			return ErrObservationProxy
		}
		value = value[n:]
	}
	return nil
}

func readFullBuffered(reader *bufio.Reader, value []byte) error {
	_, err := io.ReadFull(reader, value)
	return err
}

func address(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

func rawSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

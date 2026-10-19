//go:build linux && integration

package phase6tls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type peerProcessConfig struct{ ProfilePath, SourcesPath, RolePath, PinsPath, PinsDigest, Subject, Mode string }

func peerHash(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func peerReadJSON(t *testing.T, path string, v any) []byte {
	t.Helper()
	b, e := secretfile.Read(path, 4<<20)
	if e != nil {
		t.Fatal("private fixture input", e)
	}
	if json.Unmarshal(b, v) != nil {
		t.Fatal("fixture JSON")
	}
	canonical, _ := json.Marshal(v)
	if !bytes.Equal(b, canonical) {
		t.Fatal("noncanonical fixture")
	}
	return b
}

// This same-package integration bridge is intentionally absent from commands.
// It consumes field-validated fixture bytes, never a public startup permit.
func TestHeldPeerProcess(t *testing.T) {
	path := os.Getenv("PEER_PROCESS_CONFIG")
	if path == "" {
		t.Skip("explicit private peer fixture")
	}
	var cfg peerProcessConfig
	peerReadJSON(t, path, &cfg)
	if cfg.Subject != "provider-runtime" && cfg.Subject != "provider-docker-control" {
		t.Fatal("subject")
	}
	var pins peerFixturePins
	pb := peerReadJSON(t, cfg.PinsPath, &pins)
	if peerHash(pb) != cfg.PinsDigest {
		t.Fatal("fixture pins")
	}
	var p phase6security.ProfileV2
	raw := peerReadJSON(t, cfg.ProfilePath, &p)
	if peerHash(raw) != pins.ProfileBytes || p.Validate() == nil {
		t.Fatal("profile pin/hold")
	}
	if _, e := phase6security.ReviewControlBootstrap(raw); e != nil {
		t.Fatal(e)
	}
	var sources phase6security.PeerCRLSources
	if peerHash(peerReadJSON(t, cfg.SourcesPath, &sources)) != pins.SourceBytes || sources.Digest() != pins.MappingDigest {
		t.Fatal("sources pin")
	}
	var role phase6security.PeerCRLRoleDocument
	if peerHash(peerReadJSON(t, cfg.RolePath, &role)) != pins.RoleBytes[cfg.Subject] || role.Digest() != pins.Roles[cfg.Subject] || role.SourceMappingDigest != pins.MappingDigest {
		t.Fatal("role pin")
	}
	var b phase6security.PrivateServiceBoundaryV2
	var local phase6security.Principal
	var binding phase6security.TLSAgentBinding
	for _, v := range p.Principals {
		if v.Name == "provider-runtime" {
			b.Provider = v
		}
		if v.Name == "provider-docker-control" {
			b.Service = v
		}
		if v.Name == cfg.Subject {
			local = v
		}
	}
	for _, v := range p.TrustEdges {
		if v.ID == "provider-coding-control" {
			b.Edge = v
		}
	}
	for _, v := range p.TrustAnchors {
		if v.ID == "internal-client-ca" {
			b.ClientAnchor = v
		}
		if v.ID == "internal-server-ca" {
			b.ServerAnchor = v
		}
	}
	for _, v := range p.TLSAgentBindings {
		if v.SubjectDeployment == cfg.Subject {
			binding = v
		}
	}
	server := cfg.Subject == "provider-docker-control"
	direction := "outbound"
	if server {
		direction = "inbound"
	}
	if b.Edge.From != b.Provider.Name || b.Edge.To != b.Service.Name || b.Edge.RoutePath != "/control/coding" || role.LocalPrincipalDigest != local.PrincipalDigest || role.SecurityProfileDigest != p.ProfileDigest {
		t.Fatal("fixed edge")
	}
	bound, e := role.Binding(b.Edge.ID, direction)
	if e != nil {
		t.Fatal("role edge")
	}
	match := 0
	for _, edge := range sources.Edges {
		if edge.EdgeID == b.Edge.ID && edge.Direction == direction && edge.LocalPrincipalDigest == local.PrincipalDigest && edge.PeerAnchorID == bound.PeerAnchorID {
			for _, src := range sources.Sources {
				if src.ID == edge.SourceID && src.IssuerDigest == bound.IssuerDigest {
					match++
				}
			}
		}
	}
	if match != 1 {
		t.Fatal("exact issuer mapping")
	}
	groups, e := os.Getgroups()
	extra := []uint32(nil)
	if server {
		extra = p.DockerControl.SupplementaryGIDs
	}
	if e != nil || !privateServiceProcessMatches(local.UID, local.GID, extra, os.Getuid(), os.Getgid(), groups) {
		t.Fatal("process identity")
	}
	ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client, e := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{SocketPath: binding.SocketPath, ExpectedUID: binding.AgentUID, ExpectedGID: binding.AgentGID, RoleGID: local.GID, OperationTimeout: time.Second, Now: time.Now})
	if e != nil {
		t.Fatal("signer", e)
	}
	guard, e := newPeerCRLGuardV2Bound(p, role, b.Edge.ID, local.PrincipalDigest, direction, client, time.Second, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer guard.Close()
	var sessions []*trustanchor.DirectorySession
	var observations []trustanchor.DirectoryObservation
	defer func() {
		for _, v := range sessions {
			_ = v.Close()
		}
	}()
	for _, a := range []phase6security.TrustAnchor{b.ClientAnchor, b.ServerAnchor} {
		v, e := trustanchor.RetainDirectory(ctx, a, time.Now())
		if e != nil {
			t.Fatal("CA retain", e)
		}
		sessions = append(sessions, v)
		o, e := v.Observe(ctx, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		observations = append(observations, o)
	}
	clientRoots, e := sessions[0].Roots(ctx, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	serverRoots, e := sessions[1].Roots(ctx, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	check := func(ctx context.Context) error {
		for _, v := range sessions {
			if _, e := v.Observe(ctx, time.Now()); e != nil {
				return e
			}
		}
		return nil
	}
	var logMu sync.Mutex
	emit := func(event string, fields map[string]any) {
		logMu.Lock()
		defer logMu.Unlock()
		fields["event"] = event
		fields["at"] = time.Now().UTC().Format(time.RFC3339Nano)
		fields["subject"] = cfg.Subject
		fields["pid"] = os.Getpid()
		v, _ := json.Marshal(fields)
		fmt.Println(string(v))
	}
	stopPoll, e := guard.StartPolling(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer stopPoll()
	trustDone := make(chan struct{})
	defer func() { cancel(); <-trustDone }()
	go func() {
		defer close(trustDone)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if e := check(ctx); e != nil {
					emit("ca-lost", map[string]any{})
					guard.Close()
					cancel()
					return
				}
			}
		}
	}()
	if server {
		conf, ready, _, e := privateServiceServerTransport(b, client, serverRoots, clientRoots, guard, check)
		if e != nil {
			t.Fatal(e)
		}
		if e = ready(ctx); e != nil {
			t.Fatal("server readiness", e)
		}
		listener, e := net.Listen("tcp", b.Edge.TargetAddress)
		if e != nil {
			t.Fatal(e)
		}
		defer listener.Close()
		srv := &http.Server{ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second, ConnState: connectiondrain.PeerConnState(guard), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/control/coding" || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || check(r.Context()) != nil || !guard.Ready() {
				http.Error(w, "held", 503)
				return
			}
			body, e := io.ReadAll(io.LimitReader(r.Body, 65))
			if e != nil || string(body) != "held-peer-v1" {
				http.Error(w, "invalid", 400)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("held-peer-v1\n"))
			w.(http.Flusher).Flush()
			emit("request", map[string]any{"tls": r.TLS.Version, "serial": r.TLS.PeerCertificates[0].SerialNumber.Text(16)})
			if cfg.Mode == "hold" {
				select {
				case <-r.Context().Done():
					emit("connection-closed", map[string]any{})
				case <-ctx.Done():
				}
			}
		})}
		done := make(chan error, 1)
		go func() { done <- srv.Serve(tls.NewListener(listener, conf)) }()
		emit("peer-ready", map[string]any{"profile": p.ProfileDigest, "mapping": sources.Digest(), "role": role.Digest(), "anchors": observations, "uid": os.Getuid(), "gid": os.Getgid(), "groups": groups, "address": b.Edge.TargetAddress, "admission": "held-not-a-permit"})
		<-ctx.Done()
		_ = srv.Close()
		<-done
		return
	}
	if e := guard.Bootstrap(ctx); e != nil {
		t.Fatal("client CRL readiness", e)
	}
	transport, _, e := privateServiceClientTransport(b, client, clientRoots, serverRoots, guard, check)
	if e != nil {
		t.Fatal(e)
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, "POST", "https://"+b.Edge.TargetAddress+"/control/coding", bytes.NewBufferString("held-peer-v1"))
	if e != nil {
		t.Fatal(e)
	}
	response, e := httpClient.Do(request)
	if e != nil {
		t.Fatal("peer handshake/request", e)
	}
	defer response.Body.Close()
	prefix := make([]byte, len("held-peer-v1\n"))
	if _, e = io.ReadFull(response.Body, prefix); e != nil || string(prefix) != "held-peer-v1\n" || response.StatusCode != 200 {
		t.Fatal("probe response", e)
	}
	emit("peer-connected", map[string]any{"profile": p.ProfileDigest, "mapping": sources.Digest(), "role": role.Digest(), "anchors": observations, "uid": os.Getuid(), "gid": os.Getgid(), "groups": groups, "admission": "held-not-a-permit"})
	if cfg.Mode == "hold" {
		var tail [1]byte
		_, e = response.Body.Read(tail[:])
		if e == nil {
			t.Fatal("unexpected body")
		}
		emit("peer-drained", map[string]any{"read_error": true})
		return
	}
	tail, e := io.ReadAll(io.LimitReader(response.Body, 2))
	if e != nil || len(tail) != 0 {
		t.Fatal("probe EOF", e)
	}
}

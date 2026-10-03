// productruntimeobserver is a disposable, network-only Product readiness witness.
// It is component instrumentation, not the public ingress relay or a Guest.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	started := time.Now()
	if err := observe(os.Args[1:]); err != nil {
		_, _ = os.Stdout.WriteString("product-runtime-readiness=unavailable\n")
		os.Exit(1)
	}
	_, _ = fmt.Fprintf(os.Stdout, "product-runtime-readiness=observed elapsed_ms=%d\n",
		time.Since(started).Milliseconds())
}

// Arguments are an exact operator-derived IP, DNS SAN, URI SAN, CA bundle
// digest, expected HTTP status and finite wait. No URL or proxy is accepted.
func observe(args []string) error {
	if len(args) != 6 {
		return errors.New("observer input count")
	}
	address, err := netip.ParseAddr(args[0])
	if err != nil || !address.Is4() || address.IsLoopback() || !address.IsPrivate() {
		return errors.New("observer target")
	}
	serverName := args[1]
	if len(serverName) < 4 || len(serverName) > 253 || strings.ToLower(serverName) != serverName ||
		!strings.HasSuffix(serverName, ".sandbox-runtime.test") || strings.ContainsAny(serverName, "/:@\\ ") {
		return errors.New("observer server identity")
	}
	wantedURI, err := url.Parse(args[2])
	if err != nil || wantedURI.Scheme != "spiffe" || wantedURI.Host != "sandbox-runtime.test" ||
		wantedURI.User != nil || wantedURI.RawQuery != "" || wantedURI.Fragment != "" ||
		wantedURI.String() != args[2] {
		return errors.New("observer URI identity")
	}
	if !strings.HasPrefix(args[3], "sha256:") || len(args[3]) != len("sha256:")+64 {
		return errors.New("observer anchor digest")
	}
	expectedDigest, err := hex.DecodeString(strings.TrimPrefix(args[3], "sha256:"))
	if err != nil || "sha256:"+hex.EncodeToString(expectedDigest) != args[3] {
		return errors.New("observer canonical anchor digest")
	}
	wantedStatus, err := strconv.Atoi(args[4])
	if err != nil || (wantedStatus != http.StatusOK && wantedStatus != http.StatusServiceUnavailable) {
		return errors.New("observer status")
	}
	waitSeconds, err := strconv.Atoi(args[5])
	if err != nil || waitSeconds < 1 || waitSeconds > 20 || strconv.Itoa(waitSeconds) != args[5] {
		return errors.New("observer time bound")
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stageContext, cancelStage := context.WithTimeout(signalContext, time.Duration(waitSeconds)*time.Second)
	defer cancelStage()
	anchor, err := os.ReadFile("/etc/product-observer-ca.pem")
	if err != nil || len(anchor) == 0 || len(anchor) > 64<<10 {
		return errors.New("observer anchor unavailable")
	}
	digest := sha256.Sum256(anchor)
	if !equalDigest(digest[:], expectedDigest) {
		return errors.New("observer anchor mismatch")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(anchor) {
		return errors.New("observer anchor invalid")
	}
	target := net.JoinHostPort(address.String(), "8444")
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, requestedAddress string) (net.Conn, error) {
			if network != "tcp" || requestedAddress != net.JoinHostPort(serverName, "443") {
				return nil, errors.New("observer transport")
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", target)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: roots, ServerName: serverName,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 ||
					len(state.PeerCertificates) == 0 {
					return errors.New("observer chain")
				}
				leaf := state.PeerCertificates[0]
				if len(leaf.URIs) != 1 || leaf.URIs[0].String() != wantedURI.String() {
					return errors.New("observer principal")
				}
				return nil
			},
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("observer redirect") }}
	for {
		attemptContext, cancelAttempt := context.WithTimeout(stageContext, 3*time.Second)
		request, err := http.NewRequestWithContext(attemptContext, http.MethodGet, "https://"+serverName+"/readyz", nil)
		if err != nil {
			cancelAttempt()
			return errors.New("observer request")
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			body, bodyErr := io.ReadAll(io.LimitReader(response.Body, 256))
			_ = response.Body.Close()
			if bodyErr == nil && response.StatusCode == wantedStatus &&
				response.Header.Get("Cache-Control") == "no-store" &&
				response.Header.Get("Content-Type") == "application/json" &&
				string(body) == expectedBody(wantedStatus) {
				cancelAttempt()
				return nil
			}
		}
		cancelAttempt()
		select {
		case <-stageContext.Done():
			return errors.New("observer stage expired or canceled")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func expectedBody(status int) string {
	if status == http.StatusOK {
		return "{\"status\":\"ready\"}\n"
	}
	return "{\"status\":\"not_ready\"}\n"
}

func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

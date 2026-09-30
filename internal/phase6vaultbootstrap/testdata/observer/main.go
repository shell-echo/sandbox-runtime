// Test-only independent network observer for the real Slice 6 Vault bridge.
// It emits public fixed-issuer identity and complete-CRL metadata only.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6vaultbootstrap"
)

type observation struct {
	IssuerID      string `json:"issuer_id"`
	IssuerDigest  string `json:"issuer_digest"`
	CRLNumber     string `json:"crl_number"`
	CRLThisUpdate string `json:"crl_this_update"`
	CRLNextUpdate string `json:"crl_next_update"`
}

func main() {
	if run() != nil {
		_, _ = fmt.Fprintln(os.Stderr, "fixed Vault issuer observer failed")
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 4 {
		return errors.New("invalid argument count")
	}
	directory := "/probe"
	readPrivate := func(name string) ([]byte, error) {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 64<<10 {
			return nil, errors.New("private observer source unavailable")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Getuid()) {
			return nil, errors.New("private observer source owner changed")
		}
		return os.ReadFile(path)
	}
	serverCA, err := readPrivate("server-ca.pem")
	if err != nil {
		return err
	}
	clientCertificate, err := readPrivate("client.pem")
	if err != nil {
		return err
	}
	clientKey, err := readPrivate("client-key.pem")
	if err != nil {
		return err
	}
	rootToken, err := readPrivate("root-token")
	if err != nil {
		return err
	}
	defer clear(rootToken)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverCA) {
		return errors.New("Vault server CA unavailable")
	}
	identity, err := tls.X509KeyPair(clientCertificate, clientKey)
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "vault.sandbox-runtime.test",
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	results := make([]observation, 0, 2)
	for _, issuerID := range os.Args[2:] {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		observed, err := phase6vaultbootstrap.ObserveFixedIssuer(ctx, client, os.Args[1],
			"vault.sandbox-runtime.test", "spiffe://sandbox-runtime.test/external/vault", rootToken, issuerID, time.Now().UTC())
		cancel()
		if err != nil {
			return err
		}
		results = append(results, observation{IssuerID: observed.ID, IssuerDigest: observed.Digest,
			CRLNumber: observed.CRLNumber, CRLThisUpdate: observed.CRLThisUpdate.Format(time.RFC3339Nano),
			CRLNextUpdate: observed.CRLNextUpdate.Format(time.RFC3339Nano)})
	}
	return json.NewEncoder(os.Stdout).Encode(results)
}

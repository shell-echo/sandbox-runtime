//go:build phase5desktopgate

package productphase5gate

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	recordinglocal "github.com/shell-echo/sandbox-runtime/product/adapter/recording/local"
)

func runGatewayNode(config nodeConfig) error { //nolint:cyclop
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, config.DSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := productpostgres.New(pool, 3*time.Second)
	if err != nil {
		return err
	}
	grantKey, err := base64.RawStdEncoding.DecodeString(config.GrantKey)
	if err != nil {
		return err
	}
	grants, err := productpostgres.NewGrantRepository(store, "phase5-release-grant", grantKey)
	if err != nil {
		return err
	}
	audit, err := productpostgres.NewGatewayAuditRepository(store, product.CryptoIDGenerator{})
	if err != nil {
		return err
	}
	privateClient := mutualTLSClient(config)
	if privateClient == nil {
		return errors.New("create private Desktop client")
	}
	media, err := productgateway.NewPrivateDesktopMediaSource(productgateway.PrivateDesktopMediaOptions{
		Origin: "wss://" + config.DesktopPrivateAddress, HTTPClient: privateClient,
		ExpectedProviderID: productproviderDesktopRevision(), MaxMessageBytes: 64 << 10, OpenTimeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}
	recordingKey, err := base64.RawStdEncoding.DecodeString(config.RecordingKey)
	if err != nil {
		return err
	}
	content, err := recordinglocal.New(config.RecordingRoot, recordingKey)
	if err != nil {
		return err
	}
	redactor, err := product.NewPatternRedactor([]string{"SECRET"})
	if err != nil {
		return err
	}
	recordings, err := product.NewRecordingService(store, content, redactor, product.CryptoIDGenerator{}, nil)
	if err != nil {
		return err
	}
	recorder, err := productgateway.NewProductDesktopLiveRecorder(recordings, 3600)
	if err != nil {
		return err
	}
	handler, err := productgateway.NewDesktopLiveHandler(productgateway.DesktopLiveOptions{
		Grants: grants, Media: media, Policy: store, Transfers: &productgateway.ProductTransferDesktopAuthority{Store: store},
		Audit: audit, Recorder: recorder, AllowedOrigins: []string{publicOrigin}, MaxSignalingBytes: 96 << 10,
		MaxVideoQueue: 8, MaxAudioQueue: 8, MaxInputQueue: 8, MaxPeers: 8, MaxPeersPerSession: 1,
		AuthorityPollInterval: 25 * time.Millisecond, ConnectionTimeout: 8 * time.Second, DisconnectGrace: 300 * time.Millisecond,
		MinKeyframeInterval: 100 * time.Millisecond, MinResyncInterval: 100 * time.Millisecond, AllowHostCandidatesForTests: true,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/desktop/connect", handler)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || pool.Ping(request.Context()) != nil || !healthReady(request.Context(), privateClient, "https://"+config.DesktopPrivateAddress+"/healthz") {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	tlsConfig, err := serverTLS(config.EdgeCertificate, config.EdgeKey, "", false)
	if err != nil {
		return err
	}
	return serveUntilSignal(config.GatewayAddress, mux, tlsConfig)
}

func healthReady(ctx context.Context, client *http.Client, target string) bool {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func productproviderDesktopRevision() string {
	return "720ad15c343e71f36615dc4499edd5e764178bca"
}

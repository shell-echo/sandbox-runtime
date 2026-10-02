// guestsignerobserver is a private Slice 6 diagnostic witness. It runs as
// the actual material-agent UID/GID and prints only fixed phases and timing.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type input struct {
	SocketPath    string   `json:"socket_path"`
	SignerUID     uint32   `json:"signer_uid"`
	SignerGID     uint32   `json:"signer_gid"`
	SubjectUID    uint32   `json:"subject_uid"`
	SubjectGID    uint32   `json:"subject_gid"`
	ExpectedURI   string   `json:"expected_uri"`
	ExpectedDNS   []string `json:"expected_dns"`
	ExpectedUsage []string `json:"expected_usage"`
	MaxTTLSeconds int64    `json:"max_ttl_seconds"`
}

type result struct {
	phase                             string
	snapshotMS, certificateMS, signMS int64
	leafMask                          uint16
	durationMS, maxTTLMS              int64
}

func main() {
	result := run()
	_, _ = fmt.Fprintf(os.Stdout, "signer_probe=%s snapshot_ms=%d certificate_ms=%d sign_ms=%d leaf_mask=%03x duration_ms=%d max_ttl_ms=%d\n",
		result.phase, result.snapshotMS, result.certificateMS, result.signMS,
		result.leafMask, result.durationMS, result.maxTTLMS)
	if result.phase != "ok" {
		os.Exit(1)
	}
}

func run() result {
	valueResult := result{phase: "input", snapshotMS: -1, certificateMS: -1, signMS: -1,
		durationMS: -1, maxTTLMS: -1}
	document, err := io.ReadAll(io.LimitReader(os.Stdin, (4<<10)+1))
	if err != nil || len(document) == 0 || len(document) > 4<<10 {
		return valueResult
	}
	defer clear(document)
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value input
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF ||
		uint32(os.Getuid()) != value.SubjectUID || uint32(os.Getgid()) != value.SubjectGID ||
		value.SubjectUID == value.SignerUID || value.SubjectGID == value.SignerGID ||
		value.ExpectedURI == "" || len(value.ExpectedDNS) > 4 ||
		!slices.Equal(value.ExpectedUsage, []string{"client_auth"}) ||
		value.MaxTTLSeconds < 1 || value.MaxTTLSeconds > 86400 {
		valueResult.phase = "identity"
		return valueResult
	}
	valueResult.maxTTLMS = value.MaxTTLSeconds * 1000
	client, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: value.SocketPath, ExpectedUID: value.SignerUID,
		ExpectedGID: value.SignerGID, RoleGID: value.SubjectGID,
		OperationTimeout: 15 * time.Second, Now: time.Now})
	if err != nil {
		valueResult.phase = "socket"
		return valueResult
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	started := time.Now()
	snapshot, err := client.Snapshot(ctx)
	valueResult.snapshotMS = time.Since(started).Milliseconds()
	if err != nil {
		valueResult.phase = "snapshot"
		return valueResult
	}
	defer snapshot.Destroy()
	started = time.Now()
	certificate, err := client.CertificateForHandshake(ctx)
	valueResult.certificateMS = time.Since(started).Milliseconds()
	if err != nil || certificate.Leaf == nil {
		valueResult.phase = "certificate"
		return valueResult
	}
	valueResult.leafMask, valueResult.durationMS = checkLeaf(certificate.Leaf, snapshot.CertificateDER,
		snapshot.PublicKeyDER, value)
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	public, publicOK := certificate.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicOK {
		valueResult.phase = "key"
		return valueResult
	}
	challenge := sha256.Sum256([]byte("slice6-guest-signer-observation"))
	started = time.Now()
	signature, err := signer.Sign(nil, challenge[:], crypto.SHA256)
	valueResult.signMS = time.Since(started).Milliseconds()
	if err != nil || !ecdsa.VerifyASN1(public, challenge[:], signature) {
		valueResult.phase = "sign"
		return valueResult
	}
	clear(signature)
	valueResult.phase = "ok"
	return valueResult
}

// Each bit mirrors one fixed local-leaf condition in remotetls.validateLeaf.
// Only booleans and bounded durations cross this diagnostic process boundary.
func checkLeaf(leaf *x509.Certificate, snapshotChain [][]byte, snapshotPublic []byte, expected input) (uint16, int64) {
	var mask uint16
	if leaf == nil {
		return 0, -1
	}
	set := func(bit uint16, condition bool) {
		if condition {
			mask |= 1 << bit
		}
	}
	set(0, !leaf.IsCA && leaf.BasicConstraintsValid)
	set(1, leaf.KeyUsage == x509.KeyUsageDigitalSignature)
	set(2, slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) && len(leaf.UnknownExtKeyUsage) == 0)
	set(3, leaf.Subject.String() == "")
	set(4, len(leaf.URIs) == 1 && leaf.URIs[0] != nil && leaf.URIs[0].String() == expected.ExpectedURI)
	set(5, slices.Equal(leaf.DNSNames, expected.ExpectedDNS))
	set(6, len(leaf.IPAddresses) == 0 && len(leaf.EmailAddresses) == 0)
	now := time.Now()
	set(7, leaf.NotBefore.Before(leaf.NotAfter) && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter))
	duration := leaf.NotAfter.Sub(leaf.NotBefore)
	set(8, duration <= time.Duration(expected.MaxTTLSeconds)*time.Second)
	public, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	set(9, len(snapshotChain) > 0 && bytes.Equal(snapshotChain[0], leaf.Raw))
	set(10, err == nil && bytes.Equal(public, snapshotPublic))
	return mask, duration.Milliseconds()
}

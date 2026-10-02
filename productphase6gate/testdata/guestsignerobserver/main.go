// guestsignerobserver is a private Slice 6 diagnostic witness. It runs as
// the actual material-agent UID/GID and prints only fixed phases and timing.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type input struct {
	SocketPath string `json:"socket_path"`
	SignerUID  uint32 `json:"signer_uid"`
	SignerGID  uint32 `json:"signer_gid"`
	SubjectUID uint32 `json:"subject_uid"`
	SubjectGID uint32 `json:"subject_gid"`
}

func main() {
	phase, snapshotMS, certificateMS, signMS := run()
	_, _ = fmt.Fprintf(os.Stdout, "signer_probe=%s snapshot_ms=%d certificate_ms=%d sign_ms=%d\n",
		phase, snapshotMS, certificateMS, signMS)
	if phase != "ok" {
		os.Exit(1)
	}
}

func run() (phase string, snapshotMS, certificateMS, signMS int64) {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, (4<<10)+1))
	if err != nil || len(document) == 0 || len(document) > 4<<10 {
		return "input", -1, -1, -1
	}
	defer clear(document)
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value input
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF ||
		uint32(os.Getuid()) != value.SubjectUID || uint32(os.Getgid()) != value.SubjectGID ||
		value.SubjectUID == value.SignerUID || value.SubjectGID == value.SignerGID {
		return "identity", -1, -1, -1
	}
	client, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: value.SocketPath, ExpectedUID: value.SignerUID,
		ExpectedGID: value.SignerGID, RoleGID: value.SubjectGID,
		OperationTimeout: 15 * time.Second, Now: time.Now})
	if err != nil {
		return "socket", -1, -1, -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	started := time.Now()
	snapshot, err := client.Snapshot(ctx)
	snapshotMS = time.Since(started).Milliseconds()
	if err != nil {
		return "snapshot", snapshotMS, -1, -1
	}
	snapshot.Destroy()
	started = time.Now()
	certificate, err := client.CertificateForHandshake(ctx)
	certificateMS = time.Since(started).Milliseconds()
	if err != nil || certificate.Leaf == nil {
		return "certificate", snapshotMS, certificateMS, -1
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	public, publicOK := certificate.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicOK {
		return "key", snapshotMS, certificateMS, -1
	}
	challenge := sha256.Sum256([]byte("slice6-guest-signer-observation"))
	started = time.Now()
	signature, err := signer.Sign(nil, challenge[:], crypto.SHA256)
	signMS = time.Since(started).Milliseconds()
	if err != nil || !ecdsa.VerifyASN1(public, challenge[:], signature) {
		return "sign", snapshotMS, certificateMS, signMS
	}
	clear(signature)
	return "ok", snapshotMS, certificateMS, signMS
}

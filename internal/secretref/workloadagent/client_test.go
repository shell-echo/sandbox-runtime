package workloadagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func agentTestBinding(role secretref.Role) secretref.Binding {
	return secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://workload-agent/product-tls-certificate", Version: "v1",
		Purpose: secretref.PurposeTLSCertificate, TenantID: secretref.SystemTenant, Role: role,
	}
}

func TestClientResolvesMaterialWithUnixPeerIdentityAndRejectsReplay(t *testing.T) {
	now := time.Now().UTC()
	binding := agentTestBinding(secretref.RoleProduct)
	value := []byte("bounded certificate material")
	digest := sha256.Sum256(value)
	seen := make(map[string]struct{})
	path, await := startTestAgent(t, 2, func(connection *net.UnixConn) error {
		credentials, err := peerCredentials(connection)
		if err != nil || credentials.UID != uint32(os.Getuid()) || credentials.GID != uint32(os.Getgid()) {
			return errors.New("client peer credentials did not match")
		}
		document, err := ReadFrame(connection, maxRequestBytes)
		if err != nil {
			return err
		}
		defer clear(document)
		request, err := DecodeRequest(document, time.Now().UTC())
		if err != nil || request.Binding != binding {
			return secretref.ErrUnavailable
		}
		response := Response{Protocol: ProtocolID, Nonce: request.Nonce, RequestDigest: request.RequestDigest}
		if _, replay := seen[request.Nonce]; replay {
			response.Type, response.Status = ErrorType, StatusUnavailable
		} else {
			seen[request.Nonce] = struct{}{}
			response.Type, response.Status = MaterialType, StatusOK
			response.BindingDigest, response.Version = binding.Digest(), binding.Version
			response.Revision, response.Digest, response.State = "revision-1", "sha256:"+hex.EncodeToString(digest[:]), string(secretref.KeyActive)
			response.NotBefore, response.NotAfter = now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano)
			response.Material = append([]byte(nil), value...)
		}
		encoded, err := EncodeResponse(response, request, time.Now().UTC())
		clear(response.Material)
		if err != nil {
			return err
		}
		defer clear(encoded)
		return WriteFrame(connection, encoded, maxResponseBytes)
	})
	client, err := New(Config{
		SocketPath: path, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()),
		Role: secretref.RoleProduct, OperationTimeout: 3 * time.Second, Now: func() time.Time { return time.Now().UTC() },
		Random: bytes.NewReader(make([]byte, nonceSize*2)),
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := client.ResolveSecret(context.Background(), binding)
	if err != nil || string(material.Bytes) != string(value) || material.Revision != "revision-1" {
		t.Fatalf("ResolveSecret() = %#v, %v", material, err)
	}
	material.Destroy()
	if _, err := client.ResolveSecret(context.Background(), binding); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("replayed ResolveSecret() error = %v", err)
	}
	await()
}

func TestClientRejectsSocketAndBindingSubstitution(t *testing.T) {
	path, await := startTestAgent(t, 1, func(*net.UnixConn) error { return nil })
	base := Config{
		SocketPath: path, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()),
		Role: secretref.RoleProduct, OperationTimeout: time.Second, Now: time.Now, Random: bytes.NewReader(make([]byte, nonceSize)),
	}
	wrongOwner := base
	wrongOwner.ExpectedUID++
	if _, err := New(wrongOwner); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("wrong owner error = %v", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := New(base); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("broad socket mode error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResolveSecret(context.Background(), agentTestBinding(secretref.RoleProvider)); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("cross-role binding error = %v", err)
	}
	link := filepath.Join(filepath.Dir(path), "linked.sock")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	linked := base
	linked.SocketPath = link
	if _, err := New(linked); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("symlink socket error = %v", err)
	}
	if _, err := client.ResolveSecret(context.Background(), agentTestBinding(secretref.RoleProduct)); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("closed agent response error = %v", err)
	}
	await()
}

func TestProtocolRejectsDriftDuplicateUnknownAndTruncatedFrames(t *testing.T) {
	now := time.Now().UTC()
	binding := agentTestBinding(secretref.RoleProduct)
	nonce := strings.Repeat("A", 43)
	request, err := NewRequest(binding, nonce, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	document, err := EncodeRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"unknown":true}`)...)
	duplicate := bytes.Replace(document, []byte(`"protocol":"`+ProtocolID+`"`), []byte(`"protocol":"`+ProtocolID+`","protocol":"`+ProtocolID+`"`), 1)
	noncanonical := append(append([]byte(nil), document...), '\n')
	drifted := request
	drifted.RequestDigest = "sha256:" + strings.Repeat("0", 64)
	driftedDocument, err := json.Marshal(drifted)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{"unknown": unknown, "duplicate": duplicate, "noncanonical": noncanonical, "digest": driftedDocument} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(candidate, now); !errors.Is(err, secretref.ErrUnavailable) {
				t.Fatalf("DecodeRequest() error = %v", err)
			}
		})
	}
	frame := new(bytes.Buffer)
	if err := WriteFrame(frame, document, maxRequestBytes); err != nil {
		t.Fatal(err)
	}
	truncated := frame.Bytes()[:frame.Len()-1]
	if _, err := ReadFrame(bytes.NewReader(truncated), maxRequestBytes); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("truncated ReadFrame() error = %v", err)
	}
	over := []byte{0, 16, 0, 1}
	if _, err := ReadFrame(bytes.NewReader(over), maxRequestBytes); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("oversized ReadFrame() error = %v", err)
	}
}

func TestClientPreservesCancellationAndRejectsTrailingResponse(t *testing.T) {
	now := time.Now().UTC()
	binding := agentTestBinding(secretref.RoleProduct)
	path, await := startTestAgent(t, 1, func(connection *net.UnixConn) error {
		document, err := ReadFrame(connection, maxRequestBytes)
		if err != nil {
			return err
		}
		request, err := DecodeRequest(document, time.Now().UTC())
		clear(document)
		if err != nil {
			return err
		}
		value := []byte("certificate")
		digest := sha256.Sum256(value)
		response := Response{
			Protocol: ProtocolID, Type: MaterialType, Status: StatusOK, Nonce: request.Nonce, RequestDigest: request.RequestDigest,
			BindingDigest: binding.Digest(), Version: binding.Version, Revision: "revision-1", Digest: "sha256:" + hex.EncodeToString(digest[:]), State: string(secretref.KeyActive),
			NotBefore: now.Add(-time.Minute).Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano), Material: value,
		}
		encoded, err := EncodeResponse(response, request, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := WriteFrame(connection, encoded, maxResponseBytes); err != nil {
			return err
		}
		_, err = connection.Write([]byte("x"))
		return err
	})
	client, err := New(Config{
		SocketPath: path, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		OperationTimeout: time.Second, Now: time.Now, Random: bytes.NewReader(make([]byte, nonceSize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ResolveSecret(cancelled, binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ResolveSecret() error = %v", err)
	}
	if _, err := client.ResolveSecret(context.Background(), binding); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("trailing response error = %v", err)
	}
	await()
}

func startTestAgent(t *testing.T, connections int, handler func(*net.UnixConn) error) (string, func()) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sr-wa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if err := os.Chown(path, os.Getuid(), os.Getgid()); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		defer listener.Close()
		for index := 0; index < connections; index++ {
			connection, err := listener.AcceptUnix()
			if err != nil {
				result <- err
				return
			}
			handleErr := handler(connection)
			_ = connection.Close()
			if handleErr != nil {
				result <- fmt.Errorf("connection %d: %w", index, handleErr)
				return
			}
		}
		result <- nil
	}()
	awaited := false
	await := func() {
		if awaited {
			return
		}
		awaited = true
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("test workload agent did not stop")
		}
	}
	t.Cleanup(func() {
		_ = listener.Close()
		if !awaited {
			select {
			case <-result:
			case <-time.After(time.Second):
			}
		}
	})
	return path, await
}

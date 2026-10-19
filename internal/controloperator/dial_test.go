//go:build darwin || linux

package controloperator

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

func upgradeServer(t *testing.T, serve func(net.Conn, *bufio.Reader, *http.Request) error) (string, <-chan error) {
	t.Helper()
	// Keep below the Unix socket path limit on macOS as well as Linux.
	dir, err := os.MkdirTemp("/tmp", "control-dial-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		req, err := http.ReadRequest(r)
		if err == nil {
			_, err = io.Copy(io.Discard, req.Body)
			req.Body.Close()
		}
		if err == nil {
			err = serve(c, r, req)
		}
		done <- err
	}()
	return path, done
}

func awaitServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not observe connection close")
	}
}

func attachForTest(ctx context.Context, cli *client.Client, kind string) (client.HijackedResponse, error) {
	if kind == "exec" {
		v, err := cli.ExecAttach(ctx, "held-probe", client.ExecAttachOptions{})
		return v.HijackedResponse, err
	}
	v, err := cli.ContainerAttach(ctx, "held-control", client.ContainerAttachOptions{Stream: true, Stdin: true, Stdout: true, Stderr: true})
	return v.HijackedResponse, err
}

func TestDockerUpgradeHandshakeBounded(t *testing.T) {
	for _, kind := range []string{"attach", "exec"} {
		for _, bound := range []string{"deadline", "request-cancel", "ceremony-cancel"} {
			t.Run(kind+"/"+bound, func(t *testing.T) {
				ceremony, stop := context.WithTimeout(t.Context(), 2*time.Second)
				defer stop()
				request, cancel := context.WithCancel(context.Background())
				defer cancel()
				if bound == "deadline" {
					var deadlineCancel context.CancelFunc
					request, deadlineCancel = context.WithTimeout(request, 200*time.Millisecond)
					defer deadlineCancel()
				}
				path, done := upgradeServer(t, func(_ net.Conn, r *bufio.Reader, req *http.Request) error {
					if req.Header.Get("Upgrade") != "tcp" {
						return fmt.Errorf("missing upgrade")
					}
					if bound == "request-cancel" {
						cancel()
					} else if bound == "ceremony-cancel" {
						stop()
					}
					// Deliberately never send the HTTP upgrade response.
					b, err := io.ReadAll(r)
					if err != nil || len(b) != 0 {
						return fmt.Errorf("expected peer EOF, bytes=%d: %v", len(b), err)
					}
					return nil
				})
				cli, err := client.New(client.WithHost("unix://"+path), client.WithDialContext(dockerUnixDial(ceremony, path)), client.WithAPIVersion("1.55"))
				if err != nil {
					t.Fatal(err)
				}
				defer cli.Close()
				start := time.Now()
				stream, err := attachForTest(request, cli, kind)
				if err == nil {
					stream.Close()
					t.Fatal("accepted a handshake without a response")
				}
				if time.Since(start) > time.Second {
					t.Fatal("handshake ignored request/ceremony bound")
				}
				awaitServer(t, done)
			})
		}
	}
}

func TestDockerUpgradeRetainsHalfClose(t *testing.T) {
	for _, kind := range []string{"attach", "exec"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			path, done := upgradeServer(t, func(c net.Conn, r *bufio.Reader, _ *http.Request) error {
				// Include buffered data to exercise the SDK's additional wrapper.
				if _, err := io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\nfirst"); err != nil {
					return err
				}
				b, err := io.ReadAll(r)
				if err != nil || string(b) != "one-reply" {
					return fmt.Errorf("half-close reply: %q %v", b, err)
				}
				_, err = io.WriteString(c, "after-eof")
				return err
			})
			cli, err := client.New(client.WithHost("unix://"+path), client.WithDialContext(dockerUnixDial(ctx, path)), client.WithAPIVersion("1.55"))
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			stream, err := attachForTest(ctx, cli, kind)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if _, err := io.WriteString(stream.Conn, "one-reply"); err != nil {
				t.Fatal(err)
			}
			cw, ok := stream.Conn.(client.CloseWriter)
			if !ok || cw.CloseWrite() != nil {
				t.Fatal("lost CloseWrite")
			}
			b, err := io.ReadAll(stream.Reader)
			if err != nil || string(b) != "firstafter-eof" {
				t.Fatalf("read after half-close: %q %v", b, err)
			}
			awaitServer(t, done)
		})
	}
}

func TestBoundedUnixDialRejectsOtherTargets(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for _, tc := range []struct {
		parent                   context.Context
		network, socket, address string
	}{{ctx, "tcp", "/tmp/chosen.sock", "127.0.0.1:2375"}, {ctx, "unix", "/tmp/chosen.sock", "/tmp/other.sock"}, {ctx, "unix", "relative.sock", "relative.sock"}, {context.Background(), "unix", "/tmp/chosen.sock", "/tmp/chosen.sock"}, {nil, "unix", "/tmp/chosen.sock", "/tmp/chosen.sock"}} {
		c, err := boundedUnixDial(tc.parent, tc.socket)(ctx, tc.network, tc.address)
		if c != nil || err == nil {
			t.Fatal("accepted an unbounded or different endpoint")
		}
	}
}

func TestBoundedUnixConnectionCancelAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	path, done := upgradeServer(t, func(_ net.Conn, r *bufio.Reader, _ *http.Request) error {
		_, err := io.ReadAll(r)
		return err
	})
	// An HTTP transport can detach request cancellation for connection reuse.
	raw, err := boundedUnixDial(ctx, path)(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*boundedUnixConn)
	defer c.Close()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: local\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	for _, set := range []func(time.Time) error{c.SetDeadline, c.SetReadDeadline, c.SetWriteDeadline} {
		if err := set(time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { c.Close() })
	}
	wg.Wait()
	awaitServer(t, done)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed || len(c.stops) != 0 {
		t.Fatal("closed connection retained cancellation callbacks")
	}
}

func TestDockerUnixHTTPRoutesSelectedSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	path, done := upgradeServer(t, func(c net.Conn, _ *bufio.Reader, req *http.Request) error {
		if req.URL.Path != "/v1.55/info" || req.Host != client.DummyHost {
			return fmt.Errorf("unexpected local HTTP request")
		}
		body := `{"ID":"selected-local","OSType":"linux"}`
		_, err := fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		return err
	})
	cli, err := client.New(client.WithHost("unix://"+path), client.WithDialContext(dockerUnixDial(ctx, path)), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	info, err := cli.Info(ctx, client.InfoOptions{})
	if err != nil || info.Info.ID != "selected-local" {
		t.Fatalf("selected local HTTP route failed: %v", err)
	}
	awaitServer(t, done)
}

func TestDockerUnixHTTPBounded(t *testing.T) {
	for _, mode := range []string{"request-deadline", "ceremony-cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			request := t.Context()
			if mode == "request-deadline" {
				var stop context.CancelFunc
				request, stop = context.WithTimeout(request, 200*time.Millisecond)
				defer stop()
			}
			path, done := upgradeServer(t, func(_ net.Conn, r *bufio.Reader, _ *http.Request) error {
				if mode == "ceremony-cancel" {
					cancel()
				}
				_, err := io.ReadAll(r) // Never respond; wait for client to close.
				return err
			})
			cli, err := client.New(client.WithHost("unix://"+path), client.WithDialContext(dockerUnixDial(ctx, path)), client.WithAPIVersion("1.55"))
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			start := time.Now()
			if _, err := cli.Info(request, client.InfoOptions{}); err == nil {
				t.Fatal("accepted missing HTTP response")
			}
			if time.Since(start) > time.Second {
				t.Fatal("HTTP call ignored its bound")
			}
			awaitServer(t, done)
		})
	}
}

func TestDockerUnixDialRejectsOtherRepresentations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	path := "/tmp/selected.sock"
	for _, tc := range []struct{ network, address string }{
		{"tcp", net.JoinHostPort(path, "443")}, {"tcp", net.JoinHostPort("/tmp/other.sock", "80")},
		{"tcp4", net.JoinHostPort(path, "80")}, {"tcp", "127.0.0.1:80"},
		{"unix", "/tmp/other.sock"}, {"unixgram", path},
	} {
		c, err := dockerUnixDial(ctx, path)(ctx, tc.network, tc.address)
		if err == nil || c != nil {
			t.Fatal("accepted a different address or network")
		}
	}
}

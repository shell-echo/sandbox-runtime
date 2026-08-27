package terminalbroker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBrokerPreservesShellAcrossReconnect(t *testing.T) {
	socket := testSocketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Serve(ctx, socket, "/bin/sh", "/tmp") }()
	waitForProbe(t, socket)

	first := dialData(t, socket)
	if _, err := io.WriteString(first, "BROKER_VALUE=preserved\nprintf 'FIRST:%s\\n' \"$BROKER_VALUE\"\n"); err != nil {
		t.Fatal(err)
	}
	if output := readUntil(t, first, "FIRST:preserved"); !strings.Contains(output, "FIRST:preserved") {
		t.Fatalf("first output = %q", output)
	}
	_ = first.Close()

	second := dialData(t, socket)
	if _, err := io.WriteString(second, "printf 'SECOND:%s\\n' \"$BROKER_VALUE\"\n"); err != nil {
		t.Fatal(err)
	}
	if output := readUntil(t, second, "SECOND:preserved"); !strings.Contains(output, "SECOND:preserved") {
		t.Fatalf("reconnected output = %q", output)
	}
	_ = second.Close()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := control(stopCtx, socket, stopHandshake); err != nil {
		t.Fatalf("stop: %v", err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not stop")
	}
}

func TestBrokerRejectsUnsafePathsAndActiveReplacement(t *testing.T) {
	if err := Serve(context.Background(), "/tmp/other.sock", "/bin/sh", "/tmp"); !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("unsafe socket = %v", err)
	}
	socket := testSocketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- Serve(ctx, socket, "/bin/sh", "/tmp") }()
	waitForProbe(t, socket)
	if err := Serve(context.Background(), socket, "/bin/sh", "/tmp"); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Serve = %v", err)
	}
	cancel()
	select {
	case <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled broker did not stop")
	}
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("/tmp/sandbox-runtime-terminal-%032x.sock", time.Now().UnixNano())
}

func waitForProbe(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := control(ctx, socket, probeHandshake)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("terminal broker did not become ready")
}

func dialData(t *testing.T, socket string) *net.UnixConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := dial(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, dataHandshake); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	return connection
}

func readUntil(t *testing.T, connection *net.UnixConn, marker string) string {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	var output strings.Builder
	for {
		value, err := reader.ReadString('\n')
		output.WriteString(value)
		if strings.Contains(output.String(), marker) {
			return output.String()
		}
		if err != nil {
			t.Fatalf("read output %q: %v", output.String(), err)
		}
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	err := Run(context.Background(), []string{"unknown"}, strings.NewReader(""), io.Discard, io.Discard)
	if !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("Run = %v", err)
	}
}

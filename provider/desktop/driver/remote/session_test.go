package remote

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/sessiontermination"
)

func TestSessionFirstFrameThenDelayedInputResult(t *testing.T) {
	commandSeen := make(chan struct{})
	releaseResult := make(chan struct{})
	remote, stop := newSessionFixture(t, 2, func(connection *websocket.Conn) {
		writeRemoteFrame(t, connection, 1)
		kind, document, err := connection.Read(context.Background())
		if err != nil || kind != websocket.MessageText || !bytes.Contains(document, []byte(`"method":"input"`)) {
			t.Errorf("input command kind=%v document=%s err=%v", kind, document, err)
			return
		}
		close(commandSeen)
		<-releaseResult
		writeRemoteFrame(t, connection, 2)
		writeRemoteMessage(t, connection, desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionResultType, RequestID: "desktop-command-1", Sequence: 1, OK: true, Text: "accepted"})
		_, _, _ = connection.Read(context.Background())
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	frame, err := remote.ReadVideoRTP(ctx)
	if err != nil || len(frame) < 12 || frame[11] != 1 {
		t.Fatalf("first frame len=%d err=%v", len(frame), err)
	}
	result := make(chan desktopmedia.InputResult, 1)
	resultErr := make(chan error, 1)
	go func() {
		value, commandErr := remote.HandleInput(ctx, desktopmedia.Input{Sequence: 41, Kind: "pointer", Event: "move", X: 10, Y: 20, ControlLeaseID: "lease-1", ControlFence: 41})
		result <- value
		resultErr <- commandErr
	}()
	select {
	case <-commandSeen:
	case <-ctx.Done():
		t.Fatal("input command did not reach the backend")
	}
	close(releaseResult)
	frame, err = remote.ReadVideoRTP(ctx)
	if err != nil || len(frame) < 12 || frame[11] != 2 {
		t.Fatalf("concurrent frame len=%d err=%v", len(frame), err)
	}
	if value, commandErr := <-result, <-resultErr; commandErr != nil || value.Text != "accepted" {
		t.Fatalf("input result=%#v err=%v", value, commandErr)
	}
}

func TestSessionBackpressureOwnsFirstCause(t *testing.T) {
	release := make(chan struct{})
	remote, stop := newSessionFixture(t, 2, func(connection *websocket.Conn) {
		<-release
		for sequence := byte(1); sequence <= 3; sequence++ {
			writeRemoteFrame(t, connection, sequence)
		}
		_, _, _ = connection.Read(context.Background())
	})
	defer stop()
	close(release)
	select {
	case <-remote.done:
	case <-time.After(5 * time.Second):
		t.Fatal("bounded media queue did not terminate")
	}
	record, ok := remote.termination.Load()
	if !ok || record != (sessiontermination.Record{Stage: sessiontermination.StageMediaReader, Cause: sessiontermination.CauseBackpressure}) {
		t.Fatalf("termination record = %#v, %v", record, ok)
	}
	_ = remote.Close()
	if after, _ := remote.termination.Load(); after != record {
		t.Fatalf("cleanup overwrote first cause: before=%#v after=%#v", record, after)
	}
}

func newSessionFixture(t *testing.T, queue int, serve func(*websocket.Conn)) (*session, func()) {
	t.Helper()
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			close(serverDone)
			return
		}
		defer close(serverDone)
		defer connection.CloseNow()
		serve(connection)
	}))
	connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	lifecycleContext, lifecycleCancel := context.WithTimeout(context.Background(), time.Minute)
	value := &session{connection: connection, frames: make(chan []byte, queue), done: make(chan struct{}), results: make(map[string]chan desktopbroker.SessionMessage), lifecycleContext: lifecycleContext, lifecycleCancel: lifecycleCancel}
	go value.readLoop()
	return value, func() {
		_ = value.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Error("websocket fixture did not stop")
		}
		server.Close()
	}
}

func writeRemoteFrame(t *testing.T, connection *websocket.Conn, sequence byte) {
	t.Helper()
	payload := []byte{0x80, 0x60, 0, sequence, 0, 0, 0, 1, 0, 0, 0, sequence}
	if err := connection.Write(context.Background(), websocket.MessageBinary, payload); err != nil {
		t.Errorf("write frame: %v", err)
	}
}

func writeRemoteMessage(t *testing.T, connection *websocket.Conn, message desktopbroker.SessionMessage) {
	t.Helper()
	document, err := desktopbroker.EncodeSession(message)
	if err != nil {
		t.Errorf("encode message: %v", err)
		return
	}
	if err := connection.Write(context.Background(), websocket.MessageText, bytes.TrimSuffix(document, []byte{'\n'})); err != nil {
		t.Errorf("write message: %v", err)
	}
}

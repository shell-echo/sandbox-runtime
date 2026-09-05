package caller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/sys/unix"
)

const (
	testToken     = "caller-sensitive-token-value-0001"
	testCaller    = "caller-sensitive-identity"
	testTenant    = "tenant-sensitive-identity"
	testSandbox   = "sandbox-sensitive-identity"
	testSession   = "browser-session-sensitive"
	testReference = "ref:browser-session:11111111111111111111111111111111"
	testGrant     = "grant-sensitive-identity"
)

func TestOpenAndCompleteTextAndBinaryCDPMessages(t *testing.T) {
	caFile, certificate := testPKI(t)
	textRequest := []byte(`{"id":1,"method":"Runtime.evaluate","params":{"expression":"1+1"}}`)
	textResponse := []byte(`{"id":1,"result":{"result":{"type":"number","value":2}}}`)
	textEvent := []byte(`{"method":"Runtime.consoleAPICalled","params":{"type":"log"}}`)
	otherResponse := []byte(`{"id":99,"result":{"value":"unrelated"}}`)
	binaryRequest := []byte{0x00, 0x01, 0xfe, 0xff}
	binaryResponse := []byte{0xff, 0xfe, 0x01, 0x00}
	var sawTLS13 atomic.Bool
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		if request.TLS != nil && request.TLS.Version == tls.VersionTLS13 {
			sawTLS13.Store(true)
		}
		assertGatewayRequest(t, request)
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		messageType, payload, err := connection.Read(request.Context())
		if err != nil || messageType != websocket.MessageText || !bytes.Equal(payload, textRequest) {
			t.Errorf("text request = (%v, %q, %v)", messageType, payload, err)
			return
		}
		if err := connection.Write(request.Context(), websocket.MessageText, textEvent); err != nil {
			return
		}
		if err := connection.Write(request.Context(), websocket.MessageText, otherResponse); err != nil {
			return
		}
		if err := connection.Write(request.Context(), websocket.MessageText, textResponse); err != nil {
			return
		}
		messageType, payload, err = connection.Read(request.Context())
		if err != nil || messageType != websocket.MessageBinary || !bytes.Equal(payload, binaryRequest) {
			t.Errorf("binary request = (%v, %x, %v)", messageType, payload, err)
			return
		}
		if err := connection.Write(request.Context(), websocket.MessageBinary, binaryResponse); err == nil {
			_, _, _ = connection.Read(request.Context())
		}
	})
	defer server.Close()
	client := mustNewCaller(t, testConfig(caFile, server.URL))
	defer client.Close()

	opened := client.Execute(context.Background(), openCommand(1, "connection-a"))
	if !opened.OK || !opened.Upgraded || opened.Outcome != OutcomeOpened {
		t.Fatalf("open response = %#v", opened)
	}
	called := client.Execute(context.Background(), messageCommand(2, ActionCallCDP, "connection-a", MessageText, textRequest))
	assertMessageResponse(t, called, OutcomeCompleted, MessageText, textResponse)
	event := client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 3, Action: ActionReadCDP, ConnectionID: "connection-a", TimeoutMillis: 2000})
	assertMessageResponse(t, event, OutcomeRead, MessageText, textEvent)
	other := client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 4, Action: ActionReadCDP, ConnectionID: "connection-a", TimeoutMillis: 2000})
	assertMessageResponse(t, other, OutcomeRead, MessageText, otherResponse)
	written := client.Execute(context.Background(), messageCommand(5, ActionQueueCDP, "connection-a", MessageBinary, binaryRequest))
	if !written.OK || written.Outcome != OutcomeWritten || written.PayloadBase64 != "" {
		t.Fatalf("queue response = %#v", written)
	}
	read := client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 6, Action: ActionReadCDP, ConnectionID: "connection-a", TimeoutMillis: 2000})
	assertMessageResponse(t, read, OutcomeRead, MessageBinary, binaryResponse)
	closed := client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 7, Action: ActionClose, ConnectionID: "connection-a", TimeoutMillis: 2000})
	if !closed.OK || closed.Outcome != OutcomeReleased {
		t.Fatalf("close response = %#v", closed)
	}
	if !sawTLS13.Load() {
		t.Fatal("Gateway did not observe TLS 1.3")
	}
}

func TestQueueAndReadAreConcurrentSafe(t *testing.T) {
	caFile, certificate := testPKI(t)
	accepted := make(chan struct{})
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		close(accepted)
		messageType, payload, err := connection.Read(request.Context())
		if err == nil {
			_ = connection.Write(request.Context(), messageType, payload)
		}
	})
	defer server.Close()
	client := mustNewCaller(t, testConfig(caFile, server.URL))
	defer client.Close()
	if response := client.Execute(context.Background(), openCommand(1, "connection-a")); !response.OK {
		t.Fatalf("open response = %#v", response)
	}
	<-accepted

	readDone := make(chan Response, 1)
	go func() {
		readDone <- client.Execute(context.Background(), Command{
			Version: ProtocolVersion, Sequence: 2, Action: ActionReadCDP, ConnectionID: "connection-a", TimeoutMillis: 2000,
		})
	}()
	waitForSequence(t, client, 2)
	payload := []byte(`{"id":2,"method":"Runtime.evaluate","params":{"expression":"2+2"}}`)
	written := client.Execute(context.Background(), messageCommand(3, ActionQueueCDP, "connection-a", MessageText, payload))
	if !written.OK || written.Outcome != OutcomeWritten {
		t.Fatalf("queue response = %#v", written)
	}
	select {
	case read := <-readDone:
		assertMessageResponse(t, read, OutcomeRead, MessageText, payload)
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent read did not complete")
	}
}

func TestConcurrentCallsMatchReverseOrderedResponses(t *testing.T) {
	caFile, certificate := testPKI(t)
	firstRead := make(chan struct{})
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		_, first, err := connection.Read(request.Context())
		if err != nil {
			return
		}
		close(firstRead)
		_, second, err := connection.Read(request.Context())
		if err != nil {
			return
		}
		firstID, firstOK := cdpMessageID(first)
		secondID, secondOK := cdpMessageID(second)
		if !firstOK || !secondOK {
			t.Error("requests did not carry valid CDP ids")
			return
		}
		secondResponse := []byte(`{"id":` + strconv.FormatUint(secondID, 10) + `,"result":{"order":"second"}}`)
		firstResponse := []byte(`{"id":` + strconv.FormatUint(firstID, 10) + `,"result":{"order":"first"}}`)
		if err := connection.Write(request.Context(), websocket.MessageText, secondResponse); err != nil {
			return
		}
		if err := connection.Write(request.Context(), websocket.MessageText, firstResponse); err != nil {
			return
		}
		_, _, _ = connection.Read(request.Context())
	})
	defer server.Close()
	client := mustNewCaller(t, testConfig(caFile, server.URL))
	defer client.Close()
	if response := client.Execute(context.Background(), openCommand(1, "connection-a")); !response.OK {
		t.Fatalf("open response = %#v", response)
	}
	firstDone := make(chan Response, 1)
	go func() {
		firstDone <- client.Execute(context.Background(), messageCommand(2, ActionCallCDP, "connection-a", MessageText,
			[]byte(`{"id":2,"method":"Runtime.evaluate","params":{"expression":"2"}}`)))
	}()
	<-firstRead
	secondDone := make(chan Response, 1)
	go func() {
		secondDone <- client.Execute(context.Background(), messageCommand(3, ActionCallCDP, "connection-a", MessageText,
			[]byte(`{"id":3,"method":"Runtime.evaluate","params":{"expression":"3"}}`)))
	}()
	for name, channel := range map[string]<-chan Response{"first": firstDone, "second": secondDone} {
		select {
		case response := <-channel:
			if !response.OK || response.Outcome != OutcomeCompleted {
				t.Fatalf("%s response = %#v", name, response)
			}
			payload, err := base64.StdEncoding.DecodeString(response.PayloadBase64)
			if err != nil || !bytes.Contains(payload, []byte(`"order":"`+name+`"`)) {
				t.Fatalf("%s payload = %s, error = %v", name, payload, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s call did not complete", name)
		}
	}
}

func TestCDPRequestIDsCannotBeReused(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		messageType, _, err := connection.Read(request.Context())
		if err == nil {
			_ = connection.Write(request.Context(), messageType, []byte(`{"id":7,"result":{"value":7}}`))
		}
		_, _, _ = connection.Read(request.Context())
	})
	defer server.Close()
	client := mustNewCaller(t, testConfig(caFile, server.URL))
	defer client.Close()
	if response := client.Execute(context.Background(), openCommand(1, "connection-a")); !response.OK {
		t.Fatalf("open response = %#v", response)
	}
	request := []byte(`{"id":7,"method":"Runtime.evaluate","params":{"expression":"7"}}`)
	if response := client.Execute(context.Background(), messageCommand(2, ActionQueueCDP, "connection-a", MessageText, request)); !response.OK {
		t.Fatalf("queue response = %#v", response)
	}
	duplicate := client.Execute(context.Background(), messageCommand(3, ActionCallCDP, "connection-a", MessageText, request))
	if duplicate.ErrorCode != ErrorInvalidCommand {
		t.Fatalf("duplicate id response = %#v", duplicate)
	}
	read := client.Execute(context.Background(), Command{
		Version: ProtocolVersion, Sequence: 4, Action: ActionReadCDP, ConnectionID: "connection-a", TimeoutMillis: 2000,
	})
	if !read.OK || !strings.Contains(string(mustDecodePayload(t, read)), `"id":7`) {
		t.Fatalf("original queued response = %#v", read)
	}
}

func TestCallerConnectionCountIsBounded(t *testing.T) {
	caFile, _ := testPKI(t)
	client := mustNewCaller(t, testConfig(caFile, "https://127.0.0.1:18443"))
	defer client.Close()
	client.mu.Lock()
	for index := 0; index < maxActiveConnections; index++ {
		client.connections["held-"+strconv.Itoa(index)] = nil
	}
	client.mu.Unlock()
	response := client.Execute(context.Background(), openCommand(1, "connection-new"))
	if response.ErrorCode != ErrorConnectionCapacity {
		t.Fatalf("capacity response = %#v", response)
	}
}

func TestMultipleConnectionsAndRemoteCloseProjection(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		_ = connection.Close(websocket.StatusPolicyViolation, "closed")
	})
	defer server.Close()
	client := mustNewCaller(t, testConfig(caFile, server.URL))
	defer client.Close()
	for sequence, id := range []string{"connection-a", "connection-b"} {
		if response := client.Execute(context.Background(), openCommand(uint64(sequence+1), id)); !response.OK {
			t.Fatalf("open %s = %#v", id, response)
		}
	}
	for sequence, id := range []string{"connection-a", "connection-b"} {
		response := client.Execute(context.Background(), Command{
			Version: ProtocolVersion, Sequence: uint64(sequence + 3), Action: ActionExpectClosed,
			ConnectionID: id, TimeoutMillis: 2000,
		})
		if !response.OK || response.Outcome != OutcomeClosed || response.CloseCode != int(websocket.StatusPolicyViolation) {
			t.Fatalf("expect close %s = %#v", id, response)
		}
	}
}

func TestTimeoutAndCancellationUseStableCodes(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		<-request.Context().Done()
	})
	defer server.Close()
	client := mustNewCaller(t, testConfig(caFile, server.URL))
	defer client.Close()
	if response := client.Execute(context.Background(), openCommand(1, "connection-a")); !response.OK {
		t.Fatalf("open response = %#v", response)
	}
	response := client.Execute(context.Background(), Command{
		Version: ProtocolVersion, Sequence: 2, Action: ActionReadCDP, ConnectionID: "connection-a", TimeoutMillis: 25,
	})
	if response.ErrorCode != ErrorOperationTimeout {
		t.Fatalf("read timeout = %#v", response)
	}
	closed := client.Execute(context.Background(), Command{
		Version: ProtocolVersion, Sequence: 3, Action: ActionExpectClosed, ConnectionID: "connection-a", TimeoutMillis: 100,
	})
	if !closed.OK || closed.Outcome != OutcomeClosed || closed.CloseCode != int(websocket.StatusAbnormalClosure) {
		t.Fatalf("remembered close = %#v", closed)
	}
	if response := client.Execute(context.Background(), openCommand(4, "connection-b")); !response.OK {
		t.Fatalf("second open response = %#v", response)
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := client.Execute(canceledCtx, Command{
		Version: ProtocolVersion, Sequence: 5, Action: ActionReadCDP, ConnectionID: "connection-b", TimeoutMillis: 1000,
	})
	if canceled.ErrorCode != ErrorOperationCanceled {
		t.Fatalf("canceled read = %#v", canceled)
	}
}

func TestPrivateMaterialInCDPResponseIsSuppressed(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		if _, _, err := connection.Read(request.Context()); err == nil {
			_ = connection.Write(request.Context(), websocket.MessageText, []byte(`{"id":1,"result":{"value":"`+testToken+`"}}`))
		}
	})
	defer server.Close()
	config := testConfig(caFile, server.URL)
	client := mustNewCaller(t, config)
	defer client.Close()
	if response := client.Execute(context.Background(), openCommand(1, "connection-a")); !response.OK {
		t.Fatalf("open response = %#v", response)
	}
	response := client.Execute(context.Background(), messageCommand(2, ActionCallCDP, "connection-a", MessageText, []byte(`{"id":1,"method":"Runtime.evaluate"}`)))
	if response.ErrorCode != ErrorUnsafeResponse || response.PayloadBase64 != "" || response.MessageType != "" {
		t.Fatalf("unsafe response = %#v", response)
	}
	assertResponseSanitized(t, response, config)
}

func TestPrivateScanIsNarrowAndCoversOpaqueTransportMaterial(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	client := mustNewCaller(t, config)
	defer client.Close()
	for _, forbidden := range []string{
		config.CAFile, config.Gateways["gateway-a"], config.Principals[0].Token,
		config.Endpoints[0].HandoffReference, config.GrantBindings[0].GrantID, config.GrantBindings[0].ExpiresAt,
	} {
		if !client.containsPrivate([]byte(`{"value":"` + forbidden + `"}`)) {
			t.Fatalf("private scan missed %q", forbidden)
		}
	}
	for _, ordinary := range []string{
		`{"id":1,"result":{"protocolVersion":"1.3","product":"Chrome/140.0"}}`,
		`{"id":2,"result":{"result":{"type":"number","value":2}}}`,
		`{"id":3,"result":{"value":"` + config.Principals[0].TenantID + `"}}`,
	} {
		if client.containsPrivate([]byte(ordinary)) {
			t.Fatalf("private scan rejected ordinary CDP: %s", ordinary)
		}
	}
}

func TestCallCDPRequiresPositiveIntegerID(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err == nil {
			defer connection.CloseNow()
			<-request.Context().Done()
		}
	})
	defer server.Close()
	client := mustNewCaller(t, testConfig(caFile, server.URL))
	defer client.Close()
	if response := client.Execute(context.Background(), openCommand(1, "connection-a")); !response.OK {
		t.Fatalf("open response = %#v", response)
	}
	for sequence, payload := range [][]byte{
		[]byte(`{"method":"Runtime.evaluate"}`),
		[]byte(`{"id":0,"method":"Runtime.evaluate"}`),
		[]byte(`{"id":"1","method":"Runtime.evaluate"}`),
		[]byte(`{"id":1,"id":2,"method":"Runtime.evaluate"}`),
	} {
		response := client.Execute(context.Background(), messageCommand(uint64(sequence+2), ActionCallCDP, "connection-a", MessageText, payload))
		if response.ErrorCode != ErrorInvalidCommand {
			t.Fatalf("payload %s = %#v", payload, response)
		}
	}
}

func TestCommandValidationAndShutdown(t *testing.T) {
	caFile, _ := testPKI(t)
	client := mustNewCaller(t, testConfig(caFile, "https://127.0.0.1:18443"))
	defer client.Close()
	invalid := []Command{
		{Version: 99, Sequence: 1, Action: ActionShutdown},
		{Version: ProtocolVersion, Sequence: 2, Action: ActionOpen, ConnectionID: "connection-a", GatewayID: "missing", GrantBindingID: "binding-a", TimeoutMillis: 100},
		{Version: ProtocolVersion, Sequence: 3, Action: ActionOpen, ConnectionID: "connection-a", GatewayID: "gateway-a", GrantBindingID: "missing", TimeoutMillis: 100},
		{Version: ProtocolVersion, Sequence: 4, Action: ActionQueueCDP, ConnectionID: "missing", MessageType: MessageText, PayloadBase64: "not canonical", TimeoutMillis: 100},
	}
	wantCodes := []string{ErrorInvalidCommand, ErrorUnknownGateway, ErrorUnknownGrantBinding, ErrorInvalidCommand}
	for index, command := range invalid {
		if response := client.Execute(context.Background(), command); response.ErrorCode != wantCodes[index] {
			t.Fatalf("command %d = %#v", index, response)
		}
	}
	shutdown := client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 5, Action: ActionShutdown})
	if !shutdown.OK || shutdown.Outcome != OutcomeTerminated {
		t.Fatalf("shutdown = %#v", shutdown)
	}
	if response := client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 6, Action: ActionShutdown}); response.ErrorCode != ErrorInvalidCommand {
		t.Fatalf("post-shutdown = %#v", response)
	}
}

func TestRunUsesStrictBoundedJSONL(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	input := strings.NewReader("{\"version\":1,\"sequence\":1,\"sequence\":2,\"action\":\"shutdown\"}\n" +
		"{\"version\":1,\"sequence\":1,\"action\":\"shutdown\"}\n")
	var output bytes.Buffer
	if err := Run(context.Background(), config, input, &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var invalid, shutdown Response
	if err := decoder.Decode(&invalid); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&shutdown); err != nil {
		t.Fatal(err)
	}
	if invalid.ErrorCode != ErrorInvalidCommand || invalid.Sequence != 0 || !shutdown.OK || shutdown.Sequence != 1 {
		t.Fatalf("responses = %#v %#v", invalid, shutdown)
	}
}

func TestLoadConfigRequiresStrictPrivateRegularFile(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	validPath := writeFile(t, "caller.json", encoded, 0o600)
	loaded, err := LoadConfig(validPath)
	if err != nil || loaded.Gateways["gateway-a"] != config.Gateways["gateway-a"] {
		t.Fatalf("LoadConfig() = (%#v, %v)", loaded, err)
	}
	invalid := map[string][]byte{
		"unknown":   bytes.Replace(encoded, []byte(`"ca_file"`), []byte(`"unknown":true,"ca_file"`), 1),
		"duplicate": bytes.Replace(encoded, []byte(`"ca_file"`), []byte(`"ca_file":"duplicate","ca_file"`), 1),
		"trailing":  append(append([]byte(nil), encoded...), []byte(" {}")...),
	}
	for name, contents := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeFile(t, "caller.json", contents, 0o600)); err == nil {
				t.Fatal("LoadConfig accepted unsafe JSON")
			}
		})
	}
	if _, err := LoadConfig(writeFile(t, "public.json", encoded, 0o640)); err == nil {
		t.Fatal("LoadConfig accepted a group-readable configuration")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatal("LoadConfig accepted a symlink")
	}
	fifo := filepath.Join(root, "caller.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadConfig(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("LoadConfig accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("LoadConfig blocked on a FIFO")
	}
}

func TestConfigRejectsAliasedLogicalGateways(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	config.Gateways["gateway-b"] = "https://localhost:18443"
	if _, err := New(config); err == nil {
		t.Fatal("New accepted two logical Gateways at one endpoint")
	}
}

func TestConfigRequiresOneCallerIdentity(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	config.Principals = append(config.Principals, Principal{
		ID: "principal-other", Token: strings.Repeat("z", 32), CallerID: "caller-other", TenantID: "tenant-other",
	})
	if _, err := New(config); err == nil {
		t.Fatal("New accepted more than one Controller identity")
	}
}

func TestCallerCommandHasNoProviderImplementationDependency(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/downstream-fencing-caller")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list caller dependencies: %v: %s", err, strings.TrimSpace(string(output)))
	}
	for _, dependency := range strings.Fields(string(output)) {
		if dependency == "github.com/shell-echo/sandbox-runtime" || strings.HasPrefix(dependency, "github.com/shell-echo/sandbox-runtime/") {
			t.Errorf("caller transitively imports Provider implementation package %q", dependency)
		}
	}
}

func TestErrorsAndResponsesDoNotLeakPrivateConfiguration(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	client := mustNewCaller(t, config)
	defer client.Close()
	responses := []Response{
		client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 1, Action: ActionOpen, ConnectionID: "connection-a", GatewayID: "missing", GrantBindingID: "binding-a", TimeoutMillis: 100}),
		client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 2, Action: ActionOpen, ConnectionID: "connection-a", GatewayID: "gateway-a", GrantBindingID: "missing", TimeoutMillis: 100}),
		client.Execute(context.Background(), Command{Version: ProtocolVersion, Sequence: 3, Action: ActionShutdown}),
	}
	for _, response := range responses {
		assertResponseSanitized(t, response, config)
	}

	badCA := writeFile(t, "sensitive-ca.pem", []byte("sensitive-ca-payload"), 0o600)
	config.CAFile = badCA
	_, err := New(config)
	if err == nil || strings.Contains(err.Error(), badCA) || strings.Contains(err.Error(), "sensitive-ca-payload") {
		t.Fatalf("CA error was not fixed and sanitized: %v", err)
	}
}

func testConfig(caFile, gatewayURL string) Config {
	return Config{
		CAFile:     caFile,
		Gateways:   map[string]string{"gateway-a": gatewayURL},
		Principals: []Principal{{ID: "principal-sensitive", Token: testToken, CallerID: testCaller, TenantID: testTenant}},
		Endpoints: []Endpoint{{
			ID: "endpoint-sensitive", TenantID: testTenant, SandboxID: testSandbox, BrowserSessionID: testSession,
			CapabilityProfileID: "browser-v1", HandoffReference: testReference, ConnectionGeneration: 7,
		}},
		GrantBindings: []GrantBinding{{
			ID: "binding-a", GrantID: testGrant, PrincipalID: "principal-sensitive", EndpointID: "endpoint-sensitive",
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano),
		}},
	}
}

func openCommand(sequence uint64, connectionID string) Command {
	return Command{
		Version: ProtocolVersion, Sequence: sequence, Action: ActionOpen, ConnectionID: connectionID,
		GatewayID: "gateway-a", GrantBindingID: "binding-a", TimeoutMillis: 2000,
	}
}

func messageCommand(sequence uint64, action, connectionID, messageType string, payload []byte) Command {
	return Command{
		Version: ProtocolVersion, Sequence: sequence, Action: action, ConnectionID: connectionID,
		MessageType: messageType, PayloadBase64: base64.StdEncoding.EncodeToString(payload), TimeoutMillis: 2000,
	}
}

func assertMessageResponse(t *testing.T, response Response, outcome, messageType string, payload []byte) {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(response.PayloadBase64)
	if err != nil || !response.OK || response.Outcome != outcome || response.MessageType != messageType || !bytes.Equal(decoded, payload) {
		t.Fatalf("message response = %#v, decoded = %q, error = %v", response, decoded, err)
	}
}

func mustDecodePayload(t *testing.T, response Response) []byte {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(response.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertGatewayRequest(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodGet || request.URL.Path != "/v1/browser/connect" || request.Header.Get("Authorization") != "Bearer "+testToken ||
		request.Header.Get("Origin") != "https://reference-caller.invalid" {
		t.Errorf("Gateway request method/path or fixed headers are invalid")
		return
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(query) != 9 || query.Get("grant_id") != testGrant || query.Get("caller_id") != testCaller ||
		query.Get("tenant_id") != testTenant || query.Get("sandbox_id") != testSandbox || query.Get("browser_session_id") != testSession ||
		query.Get("capability_profile_id") != "browser-v1" || query.Get("handoff_reference") != testReference ||
		query.Get("connection_generation") != "7" || query.Get("expires_at") == "" {
		t.Errorf("Gateway request binding is invalid")
	}
}

func assertResponseSanitized(t *testing.T, response Response, config Config) {
	t.Helper()
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range privateValues(config) {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, encoded)
		}
	}
	if response.PayloadBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(response.PayloadBase64)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range privateValues(config) {
			if bytes.Contains(decoded, []byte(forbidden)) {
				t.Fatalf("response payload leaked %q", forbidden)
			}
		}
	}
}

func privateValues(config Config) []string {
	return []string{
		config.CAFile, config.Gateways["gateway-a"], config.Principals[0].ID, config.Principals[0].Token,
		config.Principals[0].CallerID, config.Principals[0].TenantID, config.Endpoints[0].ID,
		config.Endpoints[0].SandboxID, config.Endpoints[0].BrowserSessionID, config.Endpoints[0].CapabilityProfileID,
		config.Endpoints[0].HandoffReference, config.GrantBindings[0].GrantID, config.GrantBindings[0].PrincipalID,
		config.GrantBindings[0].EndpointID, config.GrantBindings[0].ExpiresAt,
	}
}

func mustNewCaller(t *testing.T, config Config) *Caller {
	t.Helper()
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func waitForSequence(t *testing.T, client *Caller, sequence uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		current := client.lastSeq
		client.mu.Unlock()
		if current >= sequence {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("command did not begin")
}

func writeFile(t *testing.T, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTLSServer(t *testing.T, certificate tls.Certificate, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	return server
}

func testPKI(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "caller test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, serverKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	caFile := writeFile(t, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)
	return caFile, certificate
}

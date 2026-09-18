package productgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

var automationActionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

const maxAutomationSequence = int64(9007199254740991)

type automationAction struct {
	Type       string          `json:"type"`
	ActionID   string          `json:"action_id"`
	Sequence   int64           `json:"sequence"`
	Name       string          `json:"name"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
}

type pageTextParameters struct {
	MaxCharacters int `json:"max_characters"`
}

type cdpRequest struct {
	ID     int64          `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

type cdpResponse struct {
	ID     int64           `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

type runtimeEvaluateResult struct {
	Result struct {
		Value json.RawMessage `json:"value"`
	} `json:"result"`
	ExceptionDetails json.RawMessage `json:"exceptionDetails"`
}

type pendingAutomationAction struct {
	actionID string
	sequence int64
}

type automationIncoming struct {
	frame gateway.Frame
	err   error
}

type automationResult struct {
	Type     string           `json:"type"`
	ActionID string           `json:"action_id"`
	Sequence int64            `json:"sequence"`
	OK       bool             `json:"ok"`
	Value    json.RawMessage  `json:"value,omitempty"`
	Error    *automationError `json:"error,omitempty"`
}

type automationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type browserAutomationStream struct {
	connection      *websocket.Conn
	maxMessageBytes int64
	maxPending      int

	stateMu      sync.Mutex
	lastSequence int64
	nextCDPID    int64
	pending      map[int64]pendingAutomationAction
	incoming     chan automationIncoming
	done         chan struct{}
	closeOnce    sync.Once
	closeErr     error
}

func newBrowserAutomationStream(connection *websocket.Conn, maxMessageBytes int64, maxPending int) *browserAutomationStream {
	stream := &browserAutomationStream{
		connection: connection, maxMessageBytes: maxMessageBytes, maxPending: maxPending,
		pending: make(map[int64]pendingAutomationAction), incoming: make(chan automationIncoming, maxPending), done: make(chan struct{}),
	}
	go stream.readLoop()
	return stream
}

func (s *browserAutomationStream) Receive(ctx context.Context) (gateway.Frame, error) {
	if ctx == nil {
		return gateway.Frame{}, context.Canceled
	}
	select {
	case <-ctx.Done():
		return gateway.Frame{}, ctx.Err()
	case <-s.done:
		return gateway.Frame{}, io.EOF
	case incoming := <-s.incoming:
		return incoming.frame, incoming.err
	}
}

func (s *browserAutomationStream) readLoop() {
	for {
		frame, err := s.readAction()
		select {
		case s.incoming <- automationIncoming{frame: frame, err: err}:
		case <-s.done:
			return
		}
		if err != nil {
			return
		}
	}
}

func (s *browserAutomationStream) readAction() (gateway.Frame, error) {
	messageType, payload, err := s.connection.Read(context.Background())
	if err != nil {
		return gateway.Frame{}, err
	}
	if messageType != websocket.MessageText || int64(len(payload)) > s.maxMessageBytes {
		return gateway.Frame{}, errors.New("invalid Browser automation message")
	}
	action, err := decodeAutomationAction(payload)
	if err != nil {
		return gateway.Frame{}, err
	}

	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if action.Sequence != s.lastSequence+1 || len(s.pending) >= s.maxPending || s.nextCDPID == int64(^uint64(0)>>1) {
		return gateway.Frame{}, errors.New("invalid Browser automation action order")
	}
	s.nextCDPID++
	request, err := translateAutomationAction(s.nextCDPID, action)
	if err != nil {
		return gateway.Frame{}, err
	}
	encoded, err := json.Marshal(request)
	if err != nil || int64(len(encoded)) > s.maxMessageBytes {
		return gateway.Frame{}, errors.New("invalid Browser automation action")
	}
	s.lastSequence = action.Sequence
	s.pending[s.nextCDPID] = pendingAutomationAction{actionID: action.ActionID, sequence: action.Sequence}
	return gateway.Frame{Type: gateway.TextFrame, Payload: encoded}, nil
}

func (s *browserAutomationStream) Send(ctx context.Context, frame gateway.Frame) error {
	if frame.Type != gateway.TextFrame || int64(len(frame.Payload)) > s.maxMessageBytes {
		return errors.New("invalid private Browser response")
	}
	var response cdpResponse
	if err := rejectDuplicateAutomationMembers(frame.Payload); err != nil {
		return errors.New("invalid private Browser response")
	}
	if err := json.Unmarshal(frame.Payload, &response); err != nil || response.ID < 1 {
		return errors.New("invalid private Browser response")
	}
	s.stateMu.Lock()
	pending, ok := s.pending[response.ID]
	if ok {
		delete(s.pending, response.ID)
	}
	s.stateMu.Unlock()
	if !ok {
		return errors.New("unmatched private Browser response")
	}

	result := automationResult{Type: "result", ActionID: pending.actionID, Sequence: pending.sequence}
	switch {
	case len(response.Error) != 0 && string(response.Error) != "null":
		result.Error = &automationError{Code: "AUTOMATION_ACTION_FAILED", Message: "browser action failed"}
	case len(response.Result) == 0:
		result.Error = &automationError{Code: "AUTOMATION_PROTOCOL_ERROR", Message: "browser response was invalid"}
	default:
		var evaluated runtimeEvaluateResult
		if err := json.Unmarshal(response.Result, &evaluated); err != nil || len(evaluated.ExceptionDetails) != 0 || len(evaluated.Result.Value) == 0 || !json.Valid(evaluated.Result.Value) {
			result.Error = &automationError{Code: "AUTOMATION_ACTION_FAILED", Message: "browser action failed"}
		} else {
			result.OK = true
			result.Value = append(json.RawMessage(nil), evaluated.Result.Value...)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil || int64(len(encoded)) > s.maxMessageBytes {
		return errors.New("Browser automation result exceeds limit")
	}
	return s.connection.Write(ctx, websocket.MessageText, encoded)
}

func (s *browserAutomationStream) Close(context.Context) error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.closeErr = s.connection.CloseNow()
	})
	return s.closeErr
}

func decodeAutomationAction(payload []byte) (automationAction, error) {
	if err := rejectDuplicateAutomationMembers(payload); err != nil {
		return automationAction{}, errors.New("invalid Browser automation action")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var action automationAction
	if err := decoder.Decode(&action); err != nil {
		return automationAction{}, errors.New("invalid Browser automation action")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return automationAction{}, errors.New("invalid Browser automation action")
	}
	if action.Type != "action" || !automationActionIDPattern.MatchString(action.ActionID) || action.Sequence < 1 || action.Sequence > maxAutomationSequence {
		return automationAction{}, errors.New("invalid Browser automation action")
	}
	return action, nil
}

func translateAutomationAction(id int64, action automationAction) (cdpRequest, error) {
	request := cdpRequest{ID: id, Method: "Runtime.evaluate", Params: map[string]any{"returnByValue": true, "awaitPromise": false}}
	switch action.Name {
	case "page.info":
		if !emptyJSONObject(action.Parameters) {
			return cdpRequest{}, errors.New("invalid page.info parameters")
		}
		request.Params["expression"] = `(() => ({title: String(document.title), url: String(location.href)}))()`
	case "page.text":
		parameters := pageTextParameters{MaxCharacters: 4096}
		if len(action.Parameters) != 0 {
			if err := decodeStrictRaw(action.Parameters, &parameters); err != nil {
				return cdpRequest{}, errors.New("invalid page.text parameters")
			}
		}
		if parameters.MaxCharacters < 1 || parameters.MaxCharacters > 32768 {
			return cdpRequest{}, errors.New("invalid page.text parameters")
		}
		request.Params["expression"] = fmt.Sprintf(`(() => String(document.body ? document.body.innerText : '').slice(0,%d))()`, parameters.MaxCharacters)
	default:
		return cdpRequest{}, errors.New("unsupported Browser automation action")
	}
	return request, nil
}

func emptyJSONObject(value json.RawMessage) bool {
	if len(value) == 0 {
		return true
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(value, &object) == nil && object != nil && len(object) == 0
}

func decodeStrictRaw(value json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func rejectDuplicateAutomationMembers(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			members := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object member")
				}
				if _, duplicate := members[key]; duplicate {
					return errors.New("duplicate JSON object member")
				}
				members[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

var _ gateway.Stream = (*browserAutomationStream)(nil)

package caller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
)

const maxCommandBytes = 16 << 10

// Run processes strict JSONL commands until EOF or a successful shutdown.
func Run(ctx context.Context, config wire.CallerConfig, in io.Reader, out io.Writer) error {
	if ctx == nil || in == nil || out == nil {
		return errors.New("caller initialization failed")
	}
	caller, err := New(config)
	if err != nil {
		return errors.New("caller initialization failed")
	}
	defer caller.Close()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), maxCommandBytes)
	encoder := json.NewEncoder(out)
	for scanner.Scan() {
		command, ok := decodeCommand(scanner.Bytes())
		var response wire.Response
		if !ok {
			response = wire.Response{Version: wire.ProtocolVersion, ErrorCode: wire.ErrorInvalidCommand}
		} else {
			response = caller.Execute(ctx, command)
		}
		if err := encoder.Encode(response); err != nil {
			return errors.New("caller output failed")
		}
		if ok && command.Action == wire.ActionShutdown && response.OK {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.New("caller input failed")
	}
	return nil
}

func decodeCommand(line []byte) (wire.Command, bool) {
	if !uniqueJSONFields(line) {
		return wire.Command{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var command wire.Command
	if err := decoder.Decode(&command); err != nil {
		return wire.Command{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return wire.Command{}, false
	}
	return command, true
}

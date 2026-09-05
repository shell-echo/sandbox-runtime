package caller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

const maxCommandBytes = 96 << 10

// Run processes strict, bounded JSONL commands until EOF or shutdown.
// Cancellation interrupts active commands. The command entry point also closes
// stdin on signal; embedders using another blocking Reader must unblock it.
func Run(ctx context.Context, config Config, in io.Reader, out io.Writer) error {
	if ctx == nil || in == nil || out == nil {
		return errors.New("caller initialization failed")
	}
	client, err := New(config)
	if err != nil {
		return errors.New("caller initialization failed")
	}
	defer client.Close()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), maxCommandBytes)
	encoder := json.NewEncoder(out)
	for scanner.Scan() {
		command, ok := decodeCommand(scanner.Bytes())
		response := Response{Version: ProtocolVersion, ErrorCode: ErrorInvalidCommand}
		if ok {
			response = client.Execute(ctx, command)
		}
		if err := encoder.Encode(response); err != nil {
			return errors.New("caller output failed")
		}
		if ok && command.Action == ActionShutdown && response.OK {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.New("caller input failed")
	}
	return nil
}

func decodeCommand(line []byte) (Command, bool) {
	if len(line) == 0 || len(line) > maxCommandBytes || validateUniqueJSONFields(line) != nil {
		return Command{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var command Command
	if err := decoder.Decode(&command); err != nil {
		return Command{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Command{}, false
	}
	return command, true
}

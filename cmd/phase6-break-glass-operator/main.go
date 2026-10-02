// phase6-break-glass-operator is a finite, networkless Unix transport task.
// All business signatures are supplied externally; this command never owns
// requester, approver, operator or target private signing keys.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
)

const inputProtocol = "sandbox-runtime.phase6-break-glass-operator-input.v1"

var errUnavailable = errors.New("break-glass operator unavailable")
var approvedTargets = map[string]bool{
	"browser-action-ingress-agent": true, "gateway-agent": true, "guest-agent": true,
	"product-runtime-agent": true, "provider-runtime-agent": true,
	"provider-browser-runtime-agent": true, "provider-desktop-runtime-agent": true,
}

type inputDocument struct {
	Protocol     string                  `json:"protocol"`
	Operation    string                  `json:"operation"`
	SocketPath   string                  `json:"socket_path"`
	ExpectedUID  uint32                  `json:"expected_uid"`
	ExpectedGID  uint32                  `json:"expected_gid"`
	DirectoryGID uint32                  `json:"directory_gid"`
	TargetAgent  string                  `json:"target_agent"`
	Request      *breakglass.WireRequest `json:"request"`
	Capability   *breakglass.Capability  `json:"capability"`
}

type outputDocument struct {
	Status     string                 `json:"status"`
	Revision   int64                  `json:"revision,omitempty"`
	Capability *breakglass.Capability `json:"capability,omitempty"`
}

func main() {
	if run(context.Background(), os.Stdin, os.Stdout) != nil {
		_, _ = fmt.Fprintln(os.Stderr, "break-glass operator unavailable")
		os.Exit(1)
	}
}

func run(parent context.Context, input io.Reader, output io.Writer) error {
	if parent == nil || parent.Err() != nil || input == nil || output == nil || os.Getuid() != 20091 || os.Getgid() != 30091 {
		return errUnavailable
	}
	document, err := io.ReadAll(io.LimitReader(input, 128<<10+1))
	if err != nil || len(document) < 1 || len(document) > 128<<10 {
		return errUnavailable
	}
	defer clear(document)
	var value inputDocument
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return errUnavailable
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return errUnavailable
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) || !validInput(value) {
		return errUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	result := outputDocument{Status: "ok"}
	if value.Operation == "deliver" {
		err = breakglass.DeliverV2(ctx, breakglass.V2DeliveryConfig{SocketPath: value.SocketPath,
			ExpectedUID: value.ExpectedUID, ExpectedGID: value.ExpectedGID,
			DirectoryGID: value.DirectoryGID, TargetAgent: value.TargetAgent}, *value.Capability)
	} else {
		var response breakglass.WireResponse
		response, err = breakglass.CallV2(ctx, breakglass.V2ControllerClientConfig{SocketPath: value.SocketPath,
			ExpectedUID: value.ExpectedUID, ExpectedGID: value.ExpectedGID,
			DirectoryGID: value.DirectoryGID, Kind: "control"}, *value.Request)
		result.Revision, result.Capability = response.Revision, response.Capability
	}
	if err != nil {
		return errUnavailable
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 128<<10 {
		return errUnavailable
	}
	defer clear(encoded)
	resultBytes := append(encoded, '\n')
	count, err := output.Write(resultBytes)
	if err != nil || count != len(resultBytes) {
		return errUnavailable
	}
	return nil
}

func validInput(value inputDocument) bool {
	if value.Protocol != inputProtocol || value.ExpectedUID == 0 || value.ExpectedGID == 0 ||
		value.ExpectedUID == 20091 || value.ExpectedGID == 30091 || value.DirectoryGID != 30091 {
		return false
	}
	if value.Operation == "deliver" {
		return approvedTargets[value.TargetAgent] && value.Request == nil && value.Capability != nil &&
			value.Capability.TargetAgentID == value.TargetAgent &&
			value.SocketPath == path.Join("/run/phase6/break-glass/agents", value.TargetAgent, "break-glass.sock")
	}
	if value.TargetAgent != "" || value.Capability != nil || value.Request == nil ||
		value.Request.Protocol != breakglass.ProtocolID || value.Request.Type != value.Operation ||
		value.SocketPath != "/run/phase6/break-glass/controller/operator/break-glass.sock" {
		return false
	}
	switch value.Operation {
	case breakglass.SubmitType, breakglass.ApproveType, breakglass.IssueType, breakglass.RevokeType:
		return true
	default:
		return false
	}
}

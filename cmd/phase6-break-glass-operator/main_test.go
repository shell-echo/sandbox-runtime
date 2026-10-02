package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
)

func TestFiniteOperatorInputRejectsWrongOperationAndSocket(t *testing.T) {
	request := &breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.SubmitType,
		Request: &breakglass.AccessRequest{}}
	base := inputDocument{Protocol: inputProtocol, Operation: breakglass.SubmitType,
		SocketPath:  "/run/phase6/break-glass/controller/operator/break-glass.sock",
		ExpectedUID: 20030, ExpectedGID: 30030, DirectoryGID: 30091, Request: request}
	if !validInput(base) {
		t.Fatal("closed control task rejected")
	}
	for _, mutate := range []func(*inputDocument){
		func(v *inputDocument) { v.Operation = "consume" },
		func(v *inputDocument) { v.Operation = "issue" },
		func(v *inputDocument) { v.SocketPath = "/tmp/other.sock" },
		func(v *inputDocument) { v.DirectoryGID = 30030 },
		func(v *inputDocument) { v.Capability = &breakglass.Capability{} },
		func(v *inputDocument) { v.ExpectedUID = 20091 },
	} {
		changed := base
		mutate(&changed)
		if validInput(changed) {
			t.Fatal("unreviewed control operation admitted")
		}
	}
	delivery := inputDocument{Protocol: inputProtocol, Operation: "deliver",
		SocketPath:  "/run/phase6/break-glass/agents/guest-agent/break-glass.sock",
		ExpectedUID: 20031, ExpectedGID: 30031, DirectoryGID: 30091,
		TargetAgent: "guest-agent", Capability: &breakglass.Capability{TargetAgentID: "guest-agent"}}
	if !validInput(delivery) {
		t.Fatal("closed delivery task rejected")
	}
	delivery.TargetAgent = "gateway-agent"
	if validInput(delivery) {
		t.Fatal("cross-agent delivery admitted")
	}
}

func TestFiniteOperatorRejectsNonCanonicalAndWrongIdentityBeforeSocket(t *testing.T) {
	value := inputDocument{Protocol: inputProtocol, Operation: "submit",
		SocketPath:  "/run/phase6/break-glass/controller/operator/break-glass.sock",
		ExpectedUID: 20030, ExpectedGID: 30030, DirectoryGID: 30091,
		Request: &breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: "submit", Request: &breakglass.AccessRequest{}}}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{document, append(bytes.Clone(document), '\n'),
		bytes.Replace(document, []byte(`"operation":"submit"`), []byte(`"operation":"submit","operation":"submit"`), 1)} {
		var output bytes.Buffer
		if run(t.Context(), bytes.NewReader(invalid), &output) == nil || output.Len() != 0 {
			t.Fatal("task without exact approved identity or canonical input reached socket")
		}
	}
}

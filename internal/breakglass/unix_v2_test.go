package breakglass

import (
	"context"
	"os"
	"testing"
)

func TestV2ControllerEndpointAllowsOnlyItsDirectionAndTarget(t *testing.T) {
	agent := "guest-agent"
	control := map[string]WireRequest{
		SubmitType:  {Type: SubmitType, Request: &AccessRequest{}},
		ApproveType: {Type: ApproveType, Approval: &Approval{}},
		IssueType:   {Type: IssueType, Command: &Command{}},
		RevokeType:  {Type: RevokeType, Command: &Command{}},
	}
	for operation, request := range control {
		if !v2OperationAllowed("control", "", request) || v2OperationAllowed("consume", agent, request) {
			t.Fatalf("operation %s crossed controller endpoints", operation)
		}
	}
	consume := WireRequest{Type: ConsumeType, Consume: &Consume{TargetAgentID: agent,
		Capability: Capability{TargetAgentID: agent}}}
	if v2OperationAllowed("control", "", consume) || !v2OperationAllowed("consume", agent, consume) ||
		v2OperationAllowed("consume", "gateway-agent", consume) {
		t.Fatal("consume crossed controller endpoints or target agent")
	}
	consume.Consume.Capability.TargetAgentID = "gateway-agent"
	if v2OperationAllowed("consume", agent, consume) {
		t.Fatal("cross-agent capability reached consume authority")
	}
}

func TestV2ControllerRejectsSameUIDTransportBeforeSocketSideEffects(t *testing.T) {
	config := V2ControllerServerConfig{ServerConfig: ServerConfig{SocketPath: "/tmp/unused-break-glass-v2.sock",
		SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), MaxConnections: 4},
		Kind: "control"}
	if server, err := ListenV2Controller(config, &Controller{}); err == nil || server != nil {
		if server != nil {
			_ = server.Close()
		}
		t.Fatal("v2 controller silently admitted same-UID v1 transport")
	}
}

func TestV2AgentRejectsSameUIDAndCrossTargetDelivery(t *testing.T) {
	config := V2AgentServerConfig{AgentServerConfig: AgentServerConfig{
		SocketPath: "/tmp/unused-break-glass-agent-v2.sock", SocketUID: uint32(os.Getuid()),
		SocketGID: uint32(os.Getgid()), ExpectedOperatorUID: uint32(os.Getuid()),
		ExpectedOperatorGID: uint32(os.Getgid())}, ControllerDirectoryGID: uint32(os.Getgid())}
	if server, err := ListenAgentV2(config); err == nil || server != nil {
		if server != nil {
			_ = server.Close()
		}
		t.Fatal("v2 agent silently admitted same-UID v1 delivery transport")
	}
	if err := DeliverV2(context.Background(), V2DeliveryConfig{TargetAgent: "guest-agent"},
		Capability{TargetAgentID: "gateway-agent"}); err == nil {
		t.Fatal("cross-agent capability reached delivery socket")
	}
}

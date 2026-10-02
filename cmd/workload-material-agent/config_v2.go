package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
)

func decodeCanonicalConfig(document []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return secretref.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return secretref.ErrUnavailable
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, document) {
		clear(canonical)
		return secretref.ErrUnavailable
	}
	clear(canonical)
	return nil
}

func newCredentialIssuer(config configDocument, v2 *configDocumentV2, privateKey ed25519.PrivateKey) (credentialIssuer, error) {
	if v2 == nil {
		if config.Protocol != configProtocol {
			return nil, secretref.ErrUnavailable
		}
		client, err := workloadcredential.NewProductionClient(workloadcredential.ClientConfig{
			SocketPath: config.CredentialControllerSocket, ExpectedUID: config.CredentialControllerUID, ExpectedGID: config.CredentialControllerGID,
			AgentID: config.CredentialAgentID, Role: config.Role, Purpose: secretref.PurposeWorkloadCredential,
			PolicyID: config.CredentialPolicyID, BindingDigest: config.CredentialBinding.Digest(), BackendID: config.CredentialBackendID,
			PrivateKey: privateKey, OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now,
		})
		if err != nil {
			return nil, err
		}
		return legacyCredentialIssuer{client}, nil
	}
	if config.Protocol != configProtocolV2 || v2.Protocol != configProtocolV2 {
		return nil, secretref.ErrUnavailable
	}
	profile, err := phase6security.VerifyFile(v2.SecurityProfilePath)
	if err != nil || profile.ProfileDigest != v2.SecurityProfileDigest ||
		phase6security.VerifySlice6PrivateConfigPath(profile, config.CredentialAgentID,
			phase6security.Slice6ProfileConfigFile, v2.SecurityProfilePath) != nil ||
		phase6security.VerifySlice6FinalGateProfile(profile) != nil ||
		v2.CredentialMaxTTLSeconds < v2.CredentialTTLSeconds || v2.CredentialMaxTTLSeconds > 900 {
		return nil, secretref.ErrUnavailable
	}
	registry, err := profile.PrincipalRegistry()
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	var agent, controller *phase6security.Principal
	for index := range profile.Principals {
		candidate := &profile.Principals[index]
		switch candidate.Name {
		case config.CredentialAgentID:
			agent = candidate
		case "workload-credential-controller":
			controller = candidate
		}
	}
	if agent == nil || controller == nil || agent.AuthorizationPrincipal == nil ||
		agent.Kind != "material_agent" || agent.UID != config.SocketUID ||
		uint32(os.Getuid()) != agent.UID || uint32(os.Getgid()) != agent.GID ||
		agent.AuthorizationPrincipal.Kind != securityprincipal.KindMaterialAgent ||
		secretref.Role(agent.AuthorizationPrincipal.Role) != config.Role ||
		controller.UID != config.CredentialControllerUID || controller.GID != config.CredentialControllerGID ||
		registry.Validate(*agent.AuthorizationPrincipal) != nil {
		return nil, secretref.ErrUnavailable
	}
	materialPlan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	accessBound := false
	for _, entry := range materialPlan {
		if entry.Agent != agent.Name {
			continue
		}
		if !validV2MaterialAccessConfig(entry, config, *v2) ||
			entry.AgentPrincipal != agent.PrincipalDigest || entry.AgentUID != agent.UID ||
			entry.AgentGID != agent.GID {
			return nil, secretref.ErrUnavailable
		}
		accessBound = true
		break
	}
	if !accessBound {
		return nil, secretref.ErrUnavailable
	}
	materialSocketBound := false
	for _, materialSocket := range profile.MaterialSockets {
		if materialSocket.AgentDeployment != agent.Name {
			continue
		}
		if !validV2MaterialSocketConfig(materialSocket, config) {
			return nil, secretref.ErrUnavailable
		}
		materialSocketBound = true
		break
	}
	if !materialSocketBound {
		return nil, secretref.ErrUnavailable
	}
	if !validV2BreakGlassConfig(profile, config, *v2) ||
		!validV2BreakGlassIdentity(profile, config, privateKey.Public().(ed25519.PublicKey)) {
		return nil, secretref.ErrUnavailable
	}
	binding, boundController, boundAgent, err := profile.CredentialIssuerSocketForClient(agent.Name)
	if err != nil || binding.SocketPath != config.CredentialControllerSocket ||
		boundController.UID != controller.UID || boundController.GID != controller.GID ||
		boundAgent.UID != agent.UID || boundAgent.GID != agent.GID {
		return nil, secretref.ErrUnavailable
	}
	policy := workloadcredentialv2.Policy{ID: config.CredentialPolicyID, Registry: registry,
		Principal: *agent.AuthorizationPrincipal, Purpose: secretref.PurposeWorkloadCredential,
		BackendID: config.CredentialBackendID, BackendPolicy: v2.CredentialBackendPolicy,
		MaxTTL: time.Duration(v2.CredentialMaxTTLSeconds) * time.Second, Renewable: !config.Migration,
		PublicKey: privateKey.Public().(ed25519.PublicKey), ExpectedUID: agent.UID, ExpectedGID: agent.GID}
	if policy.Validate() != nil {
		return nil, secretref.ErrUnavailable
	}
	client, err := workloadcredentialv2.NewProductionClient(workloadcredentialv2.ClientConfig{
		SocketPath: config.CredentialControllerSocket, ExpectedUID: config.CredentialControllerUID,
		ExpectedGID: config.CredentialControllerGID, DirectoryGID: agent.GID,
		Policy: policy, PrivateKey: privateKey,
		OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now,
	})
	if err != nil {
		return nil, err
	}
	return principalCredentialIssuer{client}, nil
}

func validV2MaterialSocketConfig(binding phase6security.Slice6MaterialSocketBinding, config configDocument) bool {
	return config.CredentialAgentID == binding.AgentDeployment && config.SocketPath == binding.SocketPath &&
		config.SocketUID == binding.AgentUID && config.SocketGID == binding.OwnerGID &&
		config.ExpectedClientUID == binding.OwnerUID && config.ExpectedClientGID == binding.OwnerGID &&
		config.MaxConnections == binding.MaxConnections &&
		config.OperationTimeoutSeconds >= 1 && config.OperationTimeoutSeconds <= binding.MaxOperationSeconds
}

func validV2BreakGlassConfig(profile phase6security.Profile, config configDocument, v2 configDocumentV2) bool {
	if config.Migration {
		return config.BreakGlassSocket == "" && config.BreakGlassControllerSocket == "" &&
			v2.BreakGlassSocketGID == 0 && v2.BreakGlassControllerDirectoryGID == 0
	}
	var delivery, consume phase6security.Slice6BreakGlassSocketBinding
	for _, binding := range profile.BreakGlassSockets {
		if binding.TargetAgent != config.CredentialAgentID {
			continue
		}
		switch binding.Kind {
		case "delivery":
			if delivery.ID != "" {
				return false
			}
			delivery = binding
		case "consume":
			if consume.ID != "" {
				return false
			}
			consume = binding
		default:
			return false
		}
	}
	return delivery.ID != "" && consume.ID != "" &&
		config.BreakGlassSocket == delivery.SocketPath &&
		config.BreakGlassControllerSocket == consume.SocketPath &&
		config.BreakGlassControllerUID == consume.ServerUID && config.BreakGlassControllerGID == consume.ServerGID &&
		config.ExpectedOperatorUID == delivery.ClientUID && config.ExpectedOperatorGID == delivery.ClientGID &&
		v2.BreakGlassSocketGID == delivery.ClientGID &&
		v2.BreakGlassControllerDirectoryGID == consume.ClientGID &&
		config.SocketUID == delivery.ServerUID && uint32(os.Getgid()) == consume.ClientGID
}

func validV2BreakGlassIdentity(profile phase6security.Profile, config configDocument, public ed25519.PublicKey) bool {
	if config.Migration {
		return true
	}
	for _, actor := range profile.BreakGlassKeyAuthority.Actors {
		if actor.ID == config.CredentialAgentID {
			return actor.Kind == "target" && actor.Owner == config.CredentialAgentID &&
				actor.KeyID == "credential-"+config.CredentialAgentID &&
				actor.PublicKeyDigest == phase6security.Slice6BreakGlassPublicKeyDigest(public)
		}
	}
	return false
}

func validV2MaterialAccessConfig(entry phase6security.Slice6MaterialAccess, config configDocument, v2 configDocumentV2) bool {
	return entry.Agent != "" && entry.Agent == config.CredentialAgentID &&
		entry.Role == config.Role && entry.Migration == config.Migration &&
		entry.CredentialSocket == config.CredentialControllerSocket &&
		entry.CredentialPolicyID == config.CredentialPolicyID &&
		entry.BackendPolicy == v2.CredentialBackendPolicy &&
		reflect.DeepEqual(entry.Bindings, config.Bindings) &&
		config.VaultMount == "kv" && config.VaultReferenceAuthority == "phase6"
}

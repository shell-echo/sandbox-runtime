package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
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
		agent.Kind != "material_agent" || agent.UID != config.SocketUID || agent.GID != config.SocketGID ||
		agent.AuthorizationPrincipal.Kind != securityprincipal.KindMaterialAgent ||
		secretref.Role(agent.AuthorizationPrincipal.Role) != config.Role ||
		controller.UID != config.CredentialControllerUID || controller.GID != config.CredentialControllerGID ||
		registry.Validate(*agent.AuthorizationPrincipal) != nil {
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

package config

import (
	"strings"
	"testing"
)

func TestPhase6DependenciesRequireVersionedPrivateReferences(t *testing.T) {
	value := defaultPhase6Dependencies()
	value.Coordination = CoordinationConfig{Enabled: true, EndpointRef: "secret://coordination/endpoint", CAReference: "secret://coordination/ca", IdentityRef: "secret://coordination/identity", OperationTimeout: 3, MaxConnections: 16}
	value.ObjectStore = ObjectStoreConfig{Enabled: true, EndpointRef: "secret://objects/endpoint", CAReference: "secret://objects/ca", IdentityRef: "secret://objects/identity", Bucket: "runtime-artifacts", Prefix: "phase6", OperationTimeout: 10, MaxObjectBytes: 1 << 30}
	value.KMS = KMSConfig{Enabled: true, EndpointRef: "secret://kms/endpoint", IdentityRef: "secret://kms/identity", KeyReference: "kms://recording/key#v1", CacheSeconds: 30, OperationTimeout: 5}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Phase6DependenciesConfig){
		"inline endpoint": func(candidate *Phase6DependenciesConfig) { candidate.Coordination.EndpointRef = "postgres://inline" },
		"duplicate identity": func(candidate *Phase6DependenciesConfig) {
			candidate.ObjectStore.IdentityRef = candidate.ObjectStore.EndpointRef
		},
		"unsafe prefix": func(candidate *Phase6DependenciesConfig) { candidate.ObjectStore.Prefix = "/private" },
		"inline key":    func(candidate *Phase6DependenciesConfig) { candidate.KMS.KeyReference = strings.Repeat("x", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *value
			copy.Coordination = value.Coordination
			copy.ObjectStore = value.ObjectStore
			copy.KMS = value.KMS
			mutate(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("unsafe dependency configuration was accepted")
			}
		})
	}
}

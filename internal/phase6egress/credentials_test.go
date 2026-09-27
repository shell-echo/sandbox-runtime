package phase6egress

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCapacityCredentialsClosedAndPurposeBound(t *testing.T) {
	valid := []byte(`{"protocol":"sandbox-runtime.capacity-valkey-credentials.v1","username":"ingress_capacity","password":"not-a-log-value"}`)
	credentials, err := DecodeCapacityValkeyCredentials(valid)
	if err != nil || credentials.Username != "ingress_capacity" || credentials.Password != "not-a-log-value" ||
		strings.Contains(credentials.String(), credentials.Password) || strings.Contains(fmt.Sprintf("%#v", credentials), credentials.Password) {
		t.Fatalf("valid credentials rejected or exposed: %v", err)
	}
	for name, document := range map[string][]byte{
		"missing field":  []byte(`{"protocol":"sandbox-runtime.capacity-valkey-credentials.v1","username":"ingress_capacity"}`),
		"duplicate":      []byte(`{"protocol":"sandbox-runtime.capacity-valkey-credentials.v1","username":"ingress_capacity","username":"gateway_capacity","password":"not-a-log-value"}`),
		"unknown":        []byte(`{"protocol":"sandbox-runtime.capacity-valkey-credentials.v1","username":"ingress_capacity","password":"not-a-log-value","endpoint":"other"}`),
		"trailing":       append(append([]byte(nil), valid...), []byte(`{}`)...),
		"noncanonical":   append([]byte(" "), valid...),
		"default user":   []byte(`{"protocol":"sandbox-runtime.capacity-valkey-credentials.v1","username":"default","password":"not-a-log-value"}`),
		"empty password": []byte(`{"protocol":"sandbox-runtime.capacity-valkey-credentials.v1","username":"ingress_capacity","password":""}`),
		"oversized":      []byte(strings.Repeat("x", maxExternalCredentialBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCapacityValkeyCredentials(document); !errors.Is(err, ErrUnavailable) ||
				strings.Contains(err.Error(), "not-a-log-value") {
				t.Fatalf("unsafe credential error: %v", err)
			}
		})
	}
}

func TestWitnessDSNRequiresExactDatabaseUserAndTLS(t *testing.T) {
	target := WitnessTarget{Host: "action-history.sandbox-runtime.test", Port: 5432,
		Database: "action_history", User: "ingress_witness"}
	valid := []byte("postgres://ingress_witness:secret@action-history.sandbox-runtime.test:5432/action_history?sslmode=verify-full")
	config, err := ParseActionHistoryWitnessDSN(valid, target)
	if err != nil || config.ConnConfig.Host != target.Host || config.ConnConfig.Database != target.Database ||
		config.ConnConfig.User != target.User || config.ConnConfig.TLSConfig == nil {
		t.Fatalf("valid witness URI rejected: %v", err)
	}
	for name, document := range map[string]string{
		"wrong host":        "postgres://ingress_witness:secret@other.sandbox-runtime.test:5432/action_history?sslmode=verify-full",
		"wrong database":    "postgres://ingress_witness:secret@action-history.sandbox-runtime.test:5432/product?sslmode=verify-full",
		"wrong user":        "postgres://product:secret@action-history.sandbox-runtime.test:5432/action_history?sslmode=verify-full",
		"plaintext":         "postgres://ingress_witness:secret@action-history.sandbox-runtime.test:5432/action_history?sslmode=disable",
		"fallback":          "postgres://ingress_witness:secret@action-history.sandbox-runtime.test:5432/action_history?sslmode=verify-full&host=other",
		"duplicate sslmode": "postgres://ingress_witness:secret@action-history.sandbox-runtime.test:5432/action_history?sslmode=verify-full&sslmode=disable",
		"socket":            "postgres://ingress_witness:secret@/action_history?host=/tmp&sslmode=verify-full",
		"unknown parameter": "postgres://ingress_witness:secret@action-history.sandbox-runtime.test:5432/action_history?sslmode=verify-full&application_name=debug",
		"missing password":  "postgres://ingress_witness@action-history.sandbox-runtime.test:5432/action_history?sslmode=verify-full",
		"noncanonical":      "POSTGRES://ingress_witness:secret@action-history.sandbox-runtime.test:5432/action_history?sslmode=verify-full",
		"keyword DSN":       "host=action-history.sandbox-runtime.test user=ingress_witness password=secret",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseActionHistoryWitnessDSN([]byte(document), target); !errors.Is(err, ErrUnavailable) ||
				strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe witness URI error: %v", err)
			}
		})
	}
	t.Setenv("PGHOST", "other.sandbox-runtime.test")
	if _, err := ParseActionHistoryWitnessDSN(valid, target); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("PGHOST override accepted: %v", err)
	}
}

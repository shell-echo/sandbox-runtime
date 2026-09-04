package caller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	PhaseInitial       = "initial"
	PhaseResume        = "resume"
	ProfileCodingShell = "coding-shell"
	ProfileBrowser     = "browser"
)

type IdentityConfig struct {
	ControllerSubject string `json:"controller_subject"`
	CertificateFile   string `json:"certificate_file"`
	PrivateKeyFile    string `json:"private_key_file"`
	JWSPrivateKeyFile string `json:"jws_private_key_file"`
	JWSKeyID          string `json:"jws_key_id"`
	GatewayToken      string `json:"gateway_token"`
	GatewayCallerID   string `json:"gateway_caller_id"`
	TenantID          string `json:"tenant_id"`
	WorkOrderID       string `json:"work_order_id"`
}

type Config struct {
	Profile                  string         `json:"profile"`
	Phase                    string         `json:"phase"`
	ProviderBaseURL          string         `json:"provider_base_url"`
	GatewayBaseURL           string         `json:"gateway_base_url"`
	CAFile                   string         `json:"ca_file"`
	ProviderRevisionID       string         `json:"provider_revision_id"`
	ProviderInstanceAudience string         `json:"provider_instance_audience"`
	RuntimeImageReference    string         `json:"runtime_image_reference"`
	RuntimeImageDigest       string         `json:"runtime_image_digest"`
	RuntimeArchitecture      string         `json:"runtime_architecture"`
	GatewayAdminToken        string         `json:"gateway_admin_token"`
	ControllerA              IdentityConfig `json:"controller_a"`
	ControllerB              IdentityConfig `json:"controller_b"`
}

func LoadConfig(path string) (Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read caller configuration: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode caller configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("caller configuration has trailing input")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Profile != ProfileCodingShell && c.Profile != ProfileBrowser {
		return errors.New("caller profile must be coding-shell or browser")
	}
	if c.Phase != PhaseInitial && c.Phase != PhaseResume {
		return errors.New("caller phase must be initial or resume")
	}
	for name, value := range map[string]string{
		"provider_base_url": c.ProviderBaseURL, "gateway_base_url": c.GatewayBaseURL,
		"ca_file": c.CAFile, "provider_revision_id": c.ProviderRevisionID,
		"provider_instance_audience": c.ProviderInstanceAudience,
		"runtime_image_reference":    c.RuntimeImageReference, "runtime_image_digest": c.RuntimeImageDigest,
		"runtime_architecture": c.RuntimeArchitecture,
		"gateway_admin_token":  c.GatewayAdminToken,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if !strings.HasPrefix(c.ProviderBaseURL, "https://127.0.0.1:") || !strings.HasPrefix(c.GatewayBaseURL, "https://127.0.0.1:") {
		return errors.New("caller endpoints must use HTTPS on IPv4 loopback")
	}
	if c.ProviderBaseURL == c.GatewayBaseURL {
		return errors.New("Provider and Gateway endpoints must differ")
	}
	if !isDigest(c.RuntimeImageDigest) || (c.RuntimeArchitecture != "amd64" && c.RuntimeArchitecture != "arm64") ||
		!strings.HasPrefix(c.ProviderInstanceAudience, "urn:shell-echo:sandbox-runtime:provider-instance:") {
		return errors.New("caller runtime digest or Provider audience is invalid")
	}
	if err := c.ControllerA.validate("controller_a"); err != nil {
		return err
	}
	if err := c.ControllerB.validate("controller_b"); err != nil {
		return err
	}
	if c.ControllerA.ControllerSubject == c.ControllerB.ControllerSubject || c.ControllerA.JWSKeyID == c.ControllerB.JWSKeyID ||
		c.ControllerA.GatewayToken == c.ControllerB.GatewayToken || c.ControllerA.TenantID == c.ControllerB.TenantID {
		return errors.New("caller identities, keys, Gateway tokens, and tenants must be distinct")
	}
	return nil
}

func (i IdentityConfig) validate(name string) error {
	for field, value := range map[string]string{
		"controller_subject": i.ControllerSubject, "certificate_file": i.CertificateFile,
		"private_key_file": i.PrivateKeyFile, "jws_private_key_file": i.JWSPrivateKeyFile,
		"jws_key_id": i.JWSKeyID, "gateway_token": i.GatewayToken,
		"gateway_caller_id": i.GatewayCallerID, "tenant_id": i.TenantID, "work_order_id": i.WorkOrderID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s.%s is required", name, field)
		}
	}
	if !strings.HasPrefix(i.ControllerSubject, "spiffe://") {
		return fmt.Errorf("%s.controller_subject must be a SPIFFE URI", name)
	}
	return nil
}

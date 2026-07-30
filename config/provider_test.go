package config

import "testing"

func TestProviderConfigValidate(t *testing.T) {
	valid := defaultProviderConfig()
	if err := valid.validate(); err != nil {
		t.Fatalf("default Provider config: %v", err)
	}
	valid.RevisionID = " spr "
	if err := valid.validate(); err == nil {
		t.Fatal("expected invalid revision ID error")
	}
	valid = defaultProviderConfig()
	valid.Limits.MaxExecSeconds = 0
	if err := valid.validate(); err == nil {
		t.Fatal("expected invalid Provider limits error")
	}
}

func TestProviderConfigLoadEnvironment(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)
	t.Setenv("SANDBOX_RUNTIME_PROVIDER_REVISION_ID", "spr_env")
	t.Setenv("SANDBOX_RUNTIME_PROVIDER_LIMITS_MAX_CPU_MILLIS", "2000")
	if err := Load(""); err != nil {
		t.Fatal(err)
	}
	if Provider.RevisionID != "spr_env" || Provider.Limits.MaxCPUMillis != 2000 {
		t.Fatalf("Provider = %+v", Provider)
	}
}

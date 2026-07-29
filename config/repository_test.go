package config

import "testing"

func TestRepositoryConfigValidate(t *testing.T) {
	valid := defaultRepositoryConfig()
	if err := valid.validate(); err != nil {
		t.Fatalf("default config: %v", err)
	}
	if err := (&RepositoryConfig{Driver: RepositoryFileDriver}).validate(); err == nil {
		t.Fatal("expected empty file path error")
	}
	if err := (&RepositoryConfig{Driver: "database"}).validate(); err == nil {
		t.Fatal("expected unknown driver error")
	}
}

func TestRepositoryConfigLoadEnvironment(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)
	t.Setenv("SANDBOX_RUNTIME_REPOSITORY_DRIVER", "file")
	t.Setenv("SANDBOX_RUNTIME_REPOSITORY_FILE_PATH", "state/test.json")
	if err := Load(""); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if Repository.Driver != RepositoryFileDriver || Repository.File.Path != "state/test.json" {
		t.Fatalf("Repository = %+v", Repository)
	}
}

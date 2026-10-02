package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestMigrationPostgresConnectStagesAreClosedAndLocal(t *testing.T) {
	stages := []directPostgresStage{
		postgresStageAuthority, postgresStageSignerClient, postgresStagePeerRole,
		postgresStagePeerGuardConstruction, postgresStagePeerBootstrap,
		postgresStageTLSClient, postgresStageMaterialResolve, postgresStageDSNBinding,
		postgresStagePoolBinding, postgresStageOwnGuardConstruction, postgresStageOwnRefresh,
		postgresStagePoolCreate, postgresStageMonitorStart,
	}
	seen := make(map[directPostgresStage]bool, len(stages))
	const runtimeMessage = "direct v3 PostgreSQL peer revocation evidence is unavailable"
	for _, stage := range stages {
		if seen[stage] || stage == "" {
			t.Fatalf("duplicate or empty stage %q", stage)
		}
		seen[stage] = true
		startup := postgresStartupError(stage, runtimeMessage)
		if got := startup.Error(); got != runtimeMessage {
			t.Fatalf("runtime error changed for %q: %q", stage, got)
		}
		want := "migration v2 PostgreSQL connection is unavailable: stage=" + string(stage)
		if got := migrationPostgresConnectError(startup).Error(); got != want {
			t.Fatalf("migration stage %q: got %q", stage, got)
		}
	}
	if len(seen) != 13 || postgresStagePeerGuardConstruction == postgresStagePeerBootstrap ||
		postgresStageOwnGuardConstruction == postgresStageOwnRefresh {
		t.Fatal("constructor and live pull stages must be distinct")
	}
}

func TestMigrationPostgresConnectErrorRejectsUnknownAndMaliciousCause(t *testing.T) {
	const generic = "migration v2 PostgreSQL connection is unavailable"
	secret := "postgres://role:password@hidden.example/database?token=" + strings.Repeat("x", 32768)
	for _, failure := range []error{
		errors.New(secret),
		postgresStartupError("unknown:"+directPostgresStage(secret), secret),
		postgresStartupError("", secret),
	} {
		if got := migrationPostgresConnectError(failure).Error(); got != generic {
			t.Fatalf("untrusted cause entered local startup diagnostic: %q", got)
		}
	}
	if got := migrationPostgresConnectError(postgresStartupError(postgresStagePeerBootstrap, secret)).Error(); got != generic+": stage=peer-bootstrap" {
		t.Fatalf("trusted stage leaked cause: %q", got)
	}
}

func TestDirectPostgresPreflightFailureDoesNotOpenLaterBoundary(t *testing.T) {
	_, closePool, err := openDirectV3Postgres(context.Background(), context.Background(),
		phase6security.Profile{}, nil, directV3PostgresSettings{})
	if closePool != nil || err == nil ||
		migrationPostgresConnectError(err).Error() != "migration v2 PostgreSQL connection is unavailable: stage=authority" {
		t.Fatal("invalid local startup crossed the authority boundary")
	}
}

type fakePostgresStartupGuard struct {
	failure error
	calls   int
	closed  int
}

func (g *fakePostgresStartupGuard) Bootstrap(context.Context) error {
	g.calls++
	return g.failure
}

func (g *fakePostgresStartupGuard) Refresh(context.Context) error {
	g.calls++
	return g.failure
}

func (g *fakePostgresStartupGuard) Close() { g.closed++ }

func TestDirectPostgresGuardFailureStagesAndExactCleanup(t *testing.T) {
	ctx := context.Background()
	secretFailure := errors.New("do not show: postgres://role:password@hidden.example/db")
	for _, candidate := range []struct {
		name        string
		start       func(context.Context, *fakePostgresStartupGuard, error) error
		constructor directPostgresStage
		pull        directPostgresStage
	}{
		{"peer", func(ctx context.Context, guard *fakePostgresStartupGuard, err error) error {
			return bootstrapPostgresPeer(ctx, guard, err)
		}, postgresStagePeerGuardConstruction, postgresStagePeerBootstrap},
		{"own", func(ctx context.Context, guard *fakePostgresStartupGuard, err error) error {
			return refreshPostgresOwn(ctx, guard, err)
		}, postgresStageOwnGuardConstruction, postgresStageOwnRefresh},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			construction := &fakePostgresStartupGuard{}
			failed := candidate.start(ctx, construction, secretFailure)
			if construction.calls != 0 || construction.closed != 1 ||
				migrationPostgresConnectError(failed).Error() != "migration v2 PostgreSQL connection is unavailable: stage="+string(candidate.constructor) {
				t.Fatal("constructor failure crossed live pull or missed exact close")
			}
			pull := &fakePostgresStartupGuard{failure: secretFailure}
			failed = candidate.start(ctx, pull, nil)
			if pull.calls != 1 || pull.closed != 1 ||
				migrationPostgresConnectError(failed).Error() != "migration v2 PostgreSQL connection is unavailable: stage="+string(candidate.pull) {
				t.Fatal("live pull failure missed exact close or wrong stage")
			}
			success := &fakePostgresStartupGuard{}
			if err := candidate.start(ctx, success, nil); err != nil || success.calls != 1 || success.closed != 0 {
				t.Fatal("successful startup closed active guard")
			}
		})
	}
}

//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This E/operator observation deliberately uses the existing same-run local
// PostgreSQL superuser peer. READ ONLY narrows the action, not that user's SQL
// privileges. It is not a runtime role, additional signer, or release proof.
var (
	slice6GuestOperatorSQLMu sync.Mutex
	// An uncertain Docker/psql exit cannot admit another observer session for
	// the same run merely because the caller's context returned.
	slice6GuestOperatorUncertain     = make(map[string]bool)
	slice6GuestOperatorUncertainExec = make(map[string]string)
)

type slice6GuestOperatorTarget struct {
	Run               slice6DockerRun
	PostgresID        string
	ImageID           string
	ImageRef          string
	UID, GID          int
	TenantID          string
	WorkspaceID       string
	SlotKey           string
	SlotProfileID     string
	SlotGeneration    int64
	GuestID           string
	BindingGeneration int64
}

type slice6GuestOperatorReadback struct {
	RunID                                                 string
	ProfileDigest                                         string
	SourceProofDigest                                     string
	SettingsRecheckExecID                                 string
	SettingsRecheckDigest                                 string
	PostmasterStartMicros                                 int64
	TargetDigest                                          string
	PostgresID                                            string
	PostgresFingerprint                                   string
	SQLDigest                                             string
	OperationDigest                                       string
	ReadExecID                                            string
	CheckExecID                                           string
	ReadExecStartedUTC                                    string
	ReadExecFinishedUTC                                   string
	CheckExecStartedUTC                                   string
	CheckExecFinishedUTC                                  string
	BackendSQLDigest                                      string
	RawRow                                                []byte
	RawBackend                                            []byte
	ReadExecExitRaw                                       []byte
	CheckExecExitRaw                                      []byte
	SettingsRecheckRaw                                    []byte
	SettingsRecheckExitRaw                                []byte
	SettingsRecheckStartedUTC, SettingsRecheckFinishedUTC string
	OutputSHA256                                          string
	StartedUTC                                            string
	FinishedUTC                                           string
	State                                                 string
	NonceNull                                             bool
	DBTimeUnexpired                                       bool
	ExpiresUnixMicros                                     int64
	BackendCount                                          int
}

const slice6GuestOperatorSelect = "BEGIN READ ONLY;\n" +
	"SET LOCAL statement_timeout='3000ms';\n" +
	"SET LOCAL lock_timeout='1000ms';\n" +
	"SELECT state||'|'||(connection_nonce IS NULL)::text||'|'||" +
	"(expires_at>clock_timestamp())::text||'|'||" +
	"(floor(extract(epoch FROM expires_at)*1000000)::bigint)::text " +
	"FROM sandbox_runtime_product.guest_bindings " +
	"WHERE current_user='postgres' AND current_database()='product' " +
	"AND current_setting('transaction_read_only')='on' " +
	"AND tenant_id=:'tenant_id' AND workspace_id=:'workspace_id' " +
	"AND slot_key=:'slot_key' AND slot_profile_id=:'slot_profile_id' " +
	"AND slot_generation=:'slot_generation'::bigint " +
	"AND guest_id=:'guest_id' AND binding_generation=:'binding_generation'::bigint;\nCOMMIT;\n"

const slice6GuestOperatorBackendSelect = "BEGIN READ ONLY;\n" +
	"SET LOCAL statement_timeout='3000ms';\n" +
	"SELECT count(*)::text FROM pg_catalog.pg_stat_activity " +
	"WHERE application_name=:'application_name' AND pid<>pg_backend_pid();\nCOMMIT;\n"

func slice6GuestOperatorID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func (target slice6GuestOperatorTarget) valid() bool {
	imageParts := strings.Split(target.ImageRef, "@")
	return len(target.Run.id) == 32 && lowerHexSlice6(target.Run.id) &&
		len(target.PostgresID) == 64 && lowerHexSlice6(target.PostgresID) &&
		guestRevokeFixtureDigestGate(target.ImageID) && len(imageParts) == 2 &&
		imageParts[0] != "" && guestRevokeFixtureDigestGate(imageParts[1]) &&
		// The v2 source-locked PostgreSQL image was measured as UID:GID 70:70.
		// A different selected image requires a fresh source/OS-account review.
		target.UID == 70 && target.GID == 70 &&
		target.TenantID == "tenant-phase6-"+target.Run.id &&
		slice6GuestOperatorID(target.WorkspaceID) && target.SlotKey == "primary-code" &&
		target.SlotProfileID == "coding-shell-v1" &&
		target.SlotGeneration >= 1 && slice6GuestOperatorID(target.GuestID) &&
		target.BindingGeneration >= 1
}

func slice6CheckGuestOperatorRow(out []byte, commandErr error, overflow bool) (string, bool, bool, int64, error) {
	if commandErr != nil || overflow || len(out) < 2 || len(out) > 128 || out[len(out)-1] != '\n' ||
		bytes.Count(out, []byte{'\n'}) != 1 {
		return "", false, false, 0, errors.New("Guest operator SQL readback unavailable")
	}
	parts := strings.Split(string(out[:len(out)-1]), "|")
	if len(parts) != 4 || (parts[0] != "connected" && parts[0] != "disconnected") ||
		(parts[1] != "true" && parts[1] != "false") || parts[2] != "true" {
		return "", false, false, 0, errors.New("Guest operator SQL row drift")
	}
	expires, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || expires < 1_577_836_800_000_000 || expires > 4_102_444_800_000_000 {
		return "", false, false, 0, errors.New("Guest operator SQL expiry drift")
	}
	return parts[0], parts[1] == "true", true, expires, nil
}

// inspectGuestOperatorPG rechecks the exact run-owned PG process, selected
// image/account, immutable config/data volume names and current network map.
// Its digest is private evidence; it never exports paths or endpoints.
func slice6InspectGuestOperatorPG(ctx context.Context, target slice6GuestOperatorTarget) (string, error) {
	digest, raw, err := slice6ReadGuestOperatorPGRaw(ctx, target)
	clear(raw)
	return digest, err
}

func slice6ReadGuestOperatorPGRaw(ctx context.Context, target slice6GuestOperatorTarget) (string, []byte, error) {
	if ctx == nil || ctx.Err() != nil || !target.valid() {
		return "", nil, errors.New("Guest operator PG target invalid")
	}
	output, err, overflow := slice6DockerBounded(ctx, 16<<10, nil, "inspect", "--format",
		"{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{.Config.User}}|"+
			"{{index .Config.Labels \""+slice6RunLabel+"\"}}|{{.State.Running}}|{{.State.Pid}}|"+
			"{{.State.StartedAt}}|{{.State.OOMKilled}}|{{.RestartCount}}|"+
			"{{range .Mounts}}{{.Type}}@{{.Name}}@{{.Destination}}@{{.RW}},{{end}}|"+
			"{{json .NetworkSettings.Networks}}", target.PostgresID)
	if err != nil || overflow || len(output) < 1 || len(output) > 16<<10 {
		clear(output)
		return "", nil, errors.New("Guest operator PG process unavailable")
	}
	digest, err := slice6CheckGuestOperatorPGRaw(output, target.Run.id,
		target.PostgresID, target.ImageID, target.ImageRef)
	if err != nil {
		clear(output)
		return "", nil, err
	}
	return digest, output, nil
}

func slice6CheckGuestOperatorPGRaw(output []byte, runID, postgresID, imageID, imageRef string) (string, error) {
	if len(output) < 1 || len(output) > 16<<10 || output[len(output)-1] != '\n' ||
		len(runID) != 32 || !lowerHexSlice6(runID) ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) ||
		!guestRevokeFixtureDigestGate(imageID) || imageRef == "" {
		return "", errors.New("Guest operator PG raw identity invalid")
	}
	parts := strings.Split(strings.TrimSuffix(string(output), "\n"), "|")
	if len(parts) != 13 || parts[0] != postgresID ||
		parts[1] != "/sr-p6-postgres-"+runID || parts[2] != imageID ||
		parts[3] != imageRef || parts[4] != "70:70" || parts[5] != runID ||
		parts[6] != "true" || parts[9] != "false" || parts[10] != "0" ||
		parts[12] == "null" || parts[12] == "{}" {
		return "", errors.New("Guest operator PG identity drift")
	}
	pid, pidErr := strconv.Atoi(parts[7])
	started, startErr := time.Parse(time.RFC3339Nano, parts[8])
	if pidErr != nil || pid < 1 || pid > 1<<22 || startErr != nil || started.IsZero() {
		return "", errors.New("Guest operator PG PID1 drift")
	}
	mounts := strings.Split(strings.TrimSuffix(parts[11], ","), ",")
	configMount := "volume@sr-p6-postgres-config-" + runID + "@/pg@false"
	dataMount := "volume@sr-p6-postgres-data-" + runID + "@/var/lib/postgresql/data@true"
	if len(mounts) != 2 || !((mounts[0] == configMount && mounts[1] == dataMount) ||
		(mounts[0] == dataMount && mounts[1] == configMount)) {
		return "", errors.New("Guest operator PG volume drift")
	}
	var networks map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}
	if json.Unmarshal([]byte(parts[12]), &networks) != nil || len(networks) == 0 || len(networks) > 9 {
		return "", errors.New("Guest operator PG network map unavailable")
	}
	networkIdentity := make([]string, 0, len(networks))
	for name, network := range networks {
		if !slice6GuestOperatorID(name) {
			return "", errors.New("Guest operator PG network identity invalid")
		}
		networkIdentity = append(networkIdentity, name+"@"+network.NetworkID+"@"+network.IPAddress)
	}
	slices.Sort(mounts)
	slices.Sort(networkIdentity)
	identity := strings.Join(parts[:11], "|") + "|" + strings.Join(mounts, ",") + "|" +
		strings.Join(networkIdentity, ",")
	return slice6ReceiptSHA256([]byte(identity)), nil
}

// slice6ReadGuestOperatorPG performs one bounded fixed SELECT, then a second
// bounded read-only query proving its named SQL backend is gone. Any ambiguous
// Docker CLI, psql, backend, image/process or output result is incomplete.
func slice6ReadGuestOperatorPG(parent context.Context, target slice6GuestOperatorTarget) (slice6GuestOperatorReadback, error) {
	return slice6ReadGuestOperatorPGRecorded(parent, target, "", "", nil)
}

func slice6GuestOperatorTargetDigest(target slice6GuestOperatorTarget) string {
	identity := target.Run.id + "|" + target.PostgresID + "|" + target.TenantID + "|" +
		target.WorkspaceID + "|" + target.SlotKey + "|" + target.SlotProfileID + "|" +
		strconv.FormatInt(target.SlotGeneration, 10) + "|" + target.GuestID + "|" +
		strconv.FormatInt(target.BindingGeneration, 10)
	return slice6ReceiptSHA256([]byte("phase6-guest-operator-target.v1|" + identity))
}

func slice6ReadGuestOperatorPGRecorded(parent context.Context, target slice6GuestOperatorTarget,
	stage, sourceProof string, recorder *slice6GuestRecoveryERecorder) (slice6GuestOperatorReadback, error) {
	if parent == nil || parent.Err() != nil || !target.valid() || !slice6GuestOperatorSQLMu.TryLock() {
		return slice6GuestOperatorReadback{}, errors.New("Guest operator SQL admission unavailable")
	}
	defer slice6GuestOperatorSQLMu.Unlock()
	if slice6GuestOperatorUncertain[target.Run.id] {
		return slice6GuestOperatorReadback{}, errors.New("Guest operator SQL exit previously uncertain")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	before, err := slice6InspectGuestOperatorPG(ctx, target)
	if err != nil {
		return slice6GuestOperatorReadback{}, err
	}
	started := time.Now().UTC()
	operation := make([]byte, 8)
	if _, err := rand.Read(operation); err != nil {
		return slice6GuestOperatorReadback{}, errors.New("Guest operator operation ID unavailable")
	}
	appName := "sr-p6-rb-" + target.Run.id + "-" + hex.EncodeToString(operation)
	checkAppName := "sr-p6-check-" + target.Run.id + "-" + hex.EncodeToString(operation)
	clear(operation)
	if len(appName) > 63 || len(checkAppName) > 63 {
		return slice6GuestOperatorReadback{}, errors.New("Guest operator application identity overlong")
	}
	targetDigest := slice6GuestOperatorTargetDigest(target)
	operationDigest := slice6ReceiptSHA256([]byte(appName))
	if recorder != nil {
		if rowName, _ := slice6GuestOperatorRawNames(stage); rowName == "" ||
			!guestRevokeFixtureDigestGate(sourceProof) || recorder.runID != target.Run.id ||
			recorder.record(slice6GuestRecoverySQLKind(stage, false), slice6GuestRecoverySQLCallRef(slice6GuestOperatorRawBinding{
				Stage: stage, RunID: target.Run.id, SourceProofDigest: sourceProof,
				TargetDigest: targetDigest, PostgresID: target.PostgresID,
				OperationDigest: operationDigest})) != nil {
			return slice6GuestOperatorReadback{}, errors.New("Guest operator E SQL call journal unavailable")
		}
	}
	arguments := []string{"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
		"-v", "tenant_id=" + target.TenantID, "-v", "workspace_id=" + target.WorkspaceID,
		"-v", "slot_key=" + target.SlotKey, "-v", "slot_profile_id=" + target.SlotProfileID,
		"-v", "slot_generation=" + strconv.FormatInt(target.SlotGeneration, 10),
		"-v", "guest_id=" + target.GuestID,
		"-v", "binding_generation=" + strconv.FormatInt(target.BindingGeneration, 10),
		"-h", "/var/run/postgresql", "-U", "postgres", "-d", "product", "-f", "-"}
	query := []byte(slice6GuestOperatorSelect)
	readExec, commandErr := slice6RunGuestOperatorSQL(ctx, target.PostgresID, appName,
		query, arguments, 128)
	clear(query)
	output := readExec.Output
	defer clear(output)
	if commandErr != nil || slice6CheckGuestOperatorExecExitReceipt(readExec) != nil {
		slice6GuestOperatorUncertain[target.Run.id] = true
		slice6GuestOperatorUncertainExec[target.Run.id] = readExec.ID
		return slice6GuestOperatorReadback{}, errors.New("Guest operator first SQL process exit unconfirmed")
	}
	state, nonceNull, unexpired, expires, rowErr := slice6CheckGuestOperatorRow(output, nil, false)
	outputDigest := slice6ReceiptSHA256(output)
	cleanup := []byte(slice6GuestOperatorBackendSelect)
	checkExec, backendErr := slice6RunGuestOperatorSQL(ctx, target.PostgresID, checkAppName,
		cleanup, []string{"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
			"-v", "application_name=" + appName,
			"-h", "/var/run/postgresql", "-U", "postgres", "-d", "product", "-f", "-"}, 32)
	clear(cleanup)
	backend := checkExec.Output
	defer clear(backend)
	if backendErr != nil || !bytes.Equal(backend, []byte("0\n")) ||
		slice6CheckGuestOperatorExecExitReceipt(checkExec) != nil {
		slice6GuestOperatorUncertain[target.Run.id] = true
		slice6GuestOperatorUncertainExec[target.Run.id] = checkExec.ID
		return slice6GuestOperatorReadback{}, errors.New("Guest operator SQL backend exit unconfirmed")
	}
	after, err := slice6InspectGuestOperatorPG(ctx, target)
	if err != nil || before != after {
		slice6GuestOperatorUncertain[target.Run.id] = true
		return slice6GuestOperatorReadback{}, errors.New("Guest operator PG process changed across readback")
	}
	if rowErr != nil {
		return slice6GuestOperatorReadback{}, rowErr
	}
	readFinished, readTimeErr := time.Parse(time.RFC3339Nano, readExec.FinishedUTC)
	checkStarted, checkTimeErr := time.Parse(time.RFC3339Nano, checkExec.StartedUTC)
	if readTimeErr != nil || checkTimeErr != nil || !checkStarted.After(readFinished) {
		slice6GuestOperatorUncertain[target.Run.id] = true
		return slice6GuestOperatorReadback{}, errors.New("Guest operator SQL execution order drift")
	}
	finished := time.Now().UTC()
	return slice6GuestOperatorReadback{RunID: target.Run.id,
		TargetDigest: targetDigest,
		PostgresID:   target.PostgresID, PostgresFingerprint: before,
		SQLDigest:       slice6ReceiptSHA256([]byte(slice6GuestOperatorSelect)),
		OperationDigest: operationDigest, OutputSHA256: outputDigest,
		ReadExecID: readExec.ID, CheckExecID: checkExec.ID,
		ReadExecStartedUTC: readExec.StartedUTC, ReadExecFinishedUTC: readExec.FinishedUTC,
		CheckExecStartedUTC: checkExec.StartedUTC, CheckExecFinishedUTC: checkExec.FinishedUTC,
		BackendSQLDigest: slice6ReceiptSHA256([]byte(slice6GuestOperatorBackendSelect)),
		RawRow:           bytes.Clone(output), RawBackend: bytes.Clone(backend),
		ReadExecExitRaw:  bytes.Clone(readExec.ExitReceipt),
		CheckExecExitRaw: bytes.Clone(checkExec.ExitReceipt),
		StartedUTC:       started.Format(time.RFC3339Nano), FinishedUTC: finished.Format(time.RFC3339Nano),
		State: state, NonceNull: nonceNull, DBTimeUnexpired: unexpired,
		ExpiresUnixMicros: expires, BackendCount: 0}, nil
}

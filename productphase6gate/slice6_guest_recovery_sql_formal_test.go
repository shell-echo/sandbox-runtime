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
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// A formal E readback requires a source/PG proof constructed from the actual
// same-run nine-network and mounted-HBA observations. The disposable local
// peer drill calls only slice6ReadGuestOperatorPG and cannot create this.
type slice6GuestOperatorFormalSource struct {
	runID, postgresID, profileDigest, imageRef, imageID string
	pgFingerprint, hbaDigest, settingsExecID            string
	settingsOutputDigest                                string
	settingsExecStartedUTC, settingsExecFinishedUTC     string
	postmasterStartMicros                               int64
	networkProofDigest                                  string
	rawProofDigest                                      string
	rawFiles                                            map[string]string
	evidence                                            *slice6ReceiptEvidenceRun
	profile                                             phase6security.Profile
	endpoints                                           map[string]slice6PostgresEndpoint
	dialerIDs                                           map[string]string
}

type slice6GuestPGMember struct {
	State     string // started, migrated_exited_removed, or not_started in bounded A-prime
	ID        string
	Migration *slice6ProductMigrationExitProof
}

// Nine bridges/HBA rows remain fixed, but a bounded A-prime run has only one
// live PostgreSQL dialer. The completed migration's original ID is removed
// after an exact exit/ledger capture; the other seven PG dialers never start.
func slice6GuestOperatorAStageState(dialer string) string {
	switch dialer {
	case "product-runtime":
		return "started"
	case "product-migration-job":
		return "migrated_exited_removed"
	case "gateway-runtime", "provider-runtime", "egress-broker-provider-browser", "egress-broker-provider-desktop",
		"provider-migration-job", "provider-browser-migration-job", "provider-desktop-migration-job":
		return "not_started"
	default:
		return ""
	}
}

func slice6ValidateGuestOperatorAStageMembers(members map[string]slice6GuestPGMember) error {
	if len(members) != 9 {
		return errors.New("formal Guest operator A-prime stage membership incomplete")
	}
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service != "postgres" {
			continue
		}
		member, found := members[path.Dialer]
		state := slice6GuestOperatorAStageState(path.Dialer)
		if !found || state == "" || member.State != state ||
			(state == "not_started" && member.ID != "") ||
			(state != "migrated_exited_removed" && member.Migration != nil) ||
			(state == "migrated_exited_removed" && member.Migration == nil) ||
			(state != "not_started" && (len(member.ID) != 64 || !lowerHexSlice6(member.ID))) {
			return errors.New("formal Guest operator A-prime stage membership drift")
		}
	}
	return nil
}

type slice6GuestOperatorExpectedState string

const (
	slice6GuestOperatorInitialConnected   slice6GuestOperatorExpectedState = "initial_connected"
	slice6GuestOperatorReleased           slice6GuestOperatorExpectedState = "released"
	slice6GuestOperatorRecoveredConnected slice6GuestOperatorExpectedState = "recovered_connected"
	slice6GuestOperatorFinalReleased      slice6GuestOperatorExpectedState = "final_released"
)

const slice6GuestOperatorFinalSettingsSQL = "BEGIN READ ONLY;\n" +
	"SET LOCAL statement_timeout='3000ms';\n" +
	"SELECT (current_user='postgres' AND current_database()='postgres' " +
	"AND current_setting('transaction_read_only')='on' " +
	"AND current_setting('ssl')='on' " +
	"AND current_setting('ssl_min_protocol_version')='TLSv1.3' " +
	"AND current_setting('hba_file')='/pg/pg_hba.conf' " +
	"AND current_setting('ssl_cert_file')='/pg/server.pem' " +
	"AND current_setting('ssl_key_file')='/pg/server-key.pem' " +
	"AND current_setting('ssl_ca_file')='/pg/client-ca.pem' " +
	"AND current_setting('ssl_crl_file')='/pg/client-crl.pem' " +
	"AND (SELECT count(*) FROM pg_catalog.pg_hba_file_rules)=12 " +
	"AND (SELECT count(*) FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL)=0)::text " +
	"||'|'||(floor(extract(epoch FROM pg_postmaster_start_time())*1000000)::bigint)::text;\nCOMMIT;\n"

func slice6ProveGuestOperatorFormalSource(ctx context.Context, target slice6GuestOperatorTarget,
	profile phase6security.Profile, endpoints []slice6PostgresEndpoint,
	members map[string]slice6GuestPGMember,
	evidence *slice6ReceiptEvidenceRun) (slice6GuestOperatorFormalSource, error) {
	if ctx == nil || ctx.Err() != nil || !target.valid() ||
		phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(endpoints) != 9 || slice6ValidateGuestOperatorAStageMembers(members) != nil ||
		evidence == nil || evidence.check() != nil || evidence.id != target.Run.id {
		return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator source invalid")
	}
	var selectedImage string
	for _, service := range profile.External {
		if service.Name == "postgres" {
			selectedImage = service.ImageReference
		}
	}
	if selectedImage == "" || selectedImage != target.ImageRef ||
		!guestRevokeFixtureDigestGate(target.ImageID) {
		return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator image drift")
	}
	hba, err := profile.PostgresServerAuth.RenderApprovedHBA(profile.ProviderDatabases)
	if err != nil || len(hba) == 0 || len(hba) > 64<<10 {
		return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator HBA source unavailable")
	}
	defer clear(hba)
	mountedHBA, err := slice6ReadGuestOperatorMountedHBA(ctx, target, hba)
	if err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	defer clear(mountedHBA)
	rawFiles := make(map[string]string, 23)
	recordRaw := func(name string, raw []byte) error {
		digest, err := evidence.writeV2GuestSourceRaw(name, raw)
		if err != nil {
			return err
		}
		rawFiles[name] = digest
		return nil
	}
	if err := recordRaw("guest-source-hba.raw", mountedHBA); err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	settings, err := slice6CheckGuestOperatorFinalPGSettings(ctx, target)
	defer clear(settings.RawOutput)
	defer clear(settings.ExitReceipt)
	if err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	if err := recordRaw("guest-source-settings.stdout", settings.RawOutput); err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	if err := recordRaw("guest-source-settings-exit.receipt", settings.ExitReceipt); err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	inventoryRaw, inventoryErr, inventoryOverflow := slice6DockerBounded(ctx, 64<<10, nil,
		"ps", "-a", "--no-trunc", "--format", "{{.ID}}|{{.Names}}")
	if inventoryErr != nil || inventoryOverflow {
		clear(inventoryRaw)
		return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator run inventory unavailable")
	}
	defer clear(inventoryRaw)
	inventory, err := slice6ParseGuestOperatorRunInventory(inventoryRaw)
	if err != nil || inventory["sr-p6-postgres-"+target.Run.id] != target.PostgresID ||
		inventory["sr-p6-product-runtime-"+target.Run.id] != members["product-runtime"].ID {
		return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator run inventory drift")
	}
	if err := recordRaw("guest-source-container-inventory.stdout", inventoryRaw); err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	meta := slice6GuestOperatorSourceMetadata{Protocol: "sandbox-runtime.phase6-guest-source.v1",
		RunID: target.Run.id, PostgresID: target.PostgresID,
		ProfileDigest: profile.ProfileDigest, ImageRef: target.ImageRef, ImageID: target.ImageID,
		HBADigest: slice6ReceiptSHA256(hba), SettingsExecID: settings.ExecID,
		SettingsOutputDigest: settings.OutputDigest,
		SettingsStartedUTC:   settings.StartedUTC, SettingsFinishedUTC: settings.FinishedUTC,
		PostmasterStartMicros: settings.PostmasterStartMicros,
		Networks:              make([]slice6GuestOperatorSourceNetwork, 0, 9)}
	byName := make(map[string]slice6PostgresEndpoint, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Network.Name == "" || byName[endpoint.Network.Name].ID != "" ||
			len(endpoint.ID) != 64 || !lowerHexSlice6(endpoint.ID) {
			return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator network list invalid")
		}
		byName[endpoint.Network.Name] = endpoint
	}
	profileNetwork := make(map[string]phase6security.Network, len(profile.Networks))
	for _, network := range profile.Networks {
		profileNetwork[network.Name] = network
	}
	seenDialers := make(map[string]bool)
	dialerIDs := make(map[string]string, len(endpoints))
	proofLines := make([]string, 0, len(endpoints))
	principalByName := make(map[string]phase6security.Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		principalByName[principal.Name] = principal
	}
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service != "postgres" {
			continue
		}
		endpoint, exists := byName[path.Network]
		network, profileExists := profileNetwork[path.Network]
		ip, ipErr := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, "postgres")
		member := members[path.Dialer]
		peerID := member.ID
		if !exists || !profileExists || ipErr != nil || endpoint.IP != ip ||
			peerID == target.PostgresID ||
			!network.Internal || network.GatewayModeIPv4 != "isolated" ||
			!slices.Equal(network.Principals, []string{path.Dialer}) ||
			!slices.Equal(network.ExternalServices, []string{"postgres"}) || seenDialers[path.Dialer] {
			return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator source edge drift")
		}
		seenDialers[path.Dialer] = true
		raw, commandErr, overflow := slice6DockerBounded(ctx, 64<<10, nil,
			"network", "inspect", endpoint.ID)
		if commandErr != nil || overflow || !slice6GuestOperatorNetworkRunLabel(raw, target.Run.id) {
			clear(raw)
			return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator network source unavailable")
		}
		observed, observeErr := slice6ObserveGuestOperatorPGStageNetwork(raw, network, member, target.PostgresID)
		if observeErr != nil || observed.NetworkID != endpoint.ID ||
			!slice6GuestOperatorEndpointPresent(observed, target.PostgresID, endpoint.IP) {
			clear(raw)
			return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator network member drift")
		}
		if err := recordRaw("guest-source-network-"+path.Network+".json", raw); err != nil {
			clear(raw)
			return slice6GuestOperatorFormalSource{}, err
		}
		clear(raw)
		principal := principalByName[path.Dialer]
		peerIP, peerIPErr := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, path.Dialer)
		memberProof := "not-started"
		var memberErr error
		if member.State == "started" {
			var dialerRaw []byte
			memberProof, dialerRaw, memberErr = slice6InspectGuestOperatorDialer(ctx, target, principal, member)
			if memberErr == nil {
				memberErr = recordRaw("guest-source-product-runtime.inspect", dialerRaw)
			}
			clear(dialerRaw)
		} else if member.State == "migrated_exited_removed" {
			var witness slice6ProductMigrationRemovedWitness
			memberProof, witness, memberErr = slice6VerifyProductMigrationRemovedProof(ctx, target, principal, member, inventoryRaw)
			if memberErr == nil {
				memberErr = recordRaw("product-migration-current-ledger.stdout", witness.CurrentLedgerRaw)
			}
			if memberErr == nil {
				memberErr = recordRaw("product-migration-current-ledger-exit.receipt", witness.CurrentLedgerExitRaw)
			}
			clear(witness.CurrentLedgerRaw)
			clear(witness.CurrentLedgerExitRaw)
			if memberErr == nil {
				meta.Migration = slice6GuestOperatorSourceMigration{
					OriginalID: member.ID, LedgerExecID: member.Migration.LedgerExecID,
					LedgerStartedUTC:         member.Migration.LedgerStartedUTC,
					LedgerFinishedUTC:        member.Migration.LedgerFinishedUTC,
					CurrentLedgerExecID:      witness.CurrentLedgerExecID,
					CurrentLedgerStartedUTC:  witness.CurrentLedgerStartedUTC,
					CurrentLedgerFinishedUTC: witness.CurrentLedgerFinishedUTC,
					ExpectedLedger:           witness.ExpectedLedger}
			}
		}
		if peerIPErr != nil || principal.Name != path.Dialer || memberErr != nil ||
			(member.State == "started" && !slice6GuestOperatorEndpointPresent(observed, peerID, peerIP)) ||
			(member.State == "not_started" &&
				inventory["sr-p6-"+path.Dialer+"-"+target.Run.id] != "") {
			return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator dialer stage drift")
		}
		if member.State == "migrated_exited_removed" {
			for name, raw := range map[string][]byte{
				"product-migration-exit.inspect":        member.Migration.ExitRaw,
				"product-migration-ledger.stdout":       member.Migration.LedgerRaw,
				"product-migration-remove.stdout":       member.Migration.RemovalRaw,
				"product-migration-ledger-exit.receipt": member.Migration.LedgerExecExitRaw,
			} {
				if err := recordRaw(name, raw); err != nil {
					return slice6GuestOperatorFormalSource{}, err
				}
			}
		}
		dialerIDs[path.Network] = peerID
		meta.Networks = append(meta.Networks, slice6GuestOperatorSourceNetwork{
			Network: network, NetworkID: endpoint.ID, PostgresIP: endpoint.IP,
			Dialer: path.Dialer, DialerState: member.State, DialerID: peerID, DialerIP: peerIP,
			PrincipalKind: principal.Kind, PrincipalImageRef: principal.ImageReference,
			PrincipalImageDigest:       principal.ImageDigest,
			PrincipalImageConfigDigest: principal.ImageConfigDigest})
		proofLines = append(proofLines, path.Network+"|"+endpoint.ID+"|"+endpoint.IP+"|"+
			member.State+"|"+peerID+"|"+peerIP+"|"+principal.ImageConfigDigest+"|"+memberProof+"|"+observed.InspectDigest)
	}
	if len(seenDialers) != len(members) || len(byName) != 9 ||
		slice6VerifyGuestOperatorPGNetworkMap(ctx, target, byName) != nil {
		return slice6GuestOperatorFormalSource{}, errors.New("formal Guest operator nine-network graph drift")
	}
	productNetworksRaw, err := slice6ReadGuestSourceProductNetworks(ctx, target.Run.id, members["product-runtime"].ID)
	if err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	defer clear(productNetworksRaw)
	if err := recordRaw("guest-source-product-networks.inspect", productNetworksRaw); err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	fingerprint, postgresRaw, err := slice6ReadGuestOperatorPGRaw(ctx, target)
	if err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	defer clear(postgresRaw)
	if err := recordRaw("guest-source-postgres.inspect", postgresRaw); err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	slices.Sort(proofLines)
	meta.PGFingerprint = fingerprint
	meta.NetworkProofDigest = slice6ReceiptSHA256([]byte(strings.Join(proofLines, "\n")))
	metaRaw, err := json.Marshal(meta)
	if err != nil || len(metaRaw) > 32<<10 {
		return slice6GuestOperatorFormalSource{}, errors.New("formal Guest source metadata oversized")
	}
	if err := recordRaw("guest-source-metadata.json", metaRaw); err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	source := slice6GuestOperatorFormalSource{runID: target.Run.id, postgresID: target.PostgresID,
		profileDigest: profile.ProfileDigest, imageRef: target.ImageRef, imageID: target.ImageID,
		pgFingerprint: fingerprint, hbaDigest: slice6ReceiptSHA256(hba),
		settingsExecID:          settings.ExecID,
		settingsOutputDigest:    settings.OutputDigest,
		settingsExecStartedUTC:  settings.StartedUTC,
		settingsExecFinishedUTC: settings.FinishedUTC,
		postmasterStartMicros:   settings.PostmasterStartMicros,
		networkProofDigest:      meta.NetworkProofDigest,
		rawProofDigest:          slice6GuestOperatorRawProofDigest(rawFiles),
		rawFiles:                rawFiles, evidence: evidence, profile: profile,
		endpoints: byName, dialerIDs: dialerIDs}
	frozenLedger, err := slice6FrozenProductMigrationLedger(ctx)
	if err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	if err := source.verifySourceSemantics(frozenLedger); err != nil {
		return slice6GuestOperatorFormalSource{}, err
	}
	return source, nil
}

func slice6ObserveGuestOperatorPGStageNetwork(raw []byte, network phase6security.Network,
	member slice6GuestPGMember, postgresID string) (phase6security.NetworkObservation, error) {
	if len(network.Principals) != 1 || len(network.ExternalServices) != 1 ||
		network.ExternalServices[0] != "postgres" ||
		slice6GuestOperatorAStageState(network.Principals[0]) != member.State ||
		(member.State == "not_started" && member.ID != "") ||
		(member.State != "not_started" && (len(member.ID) != 64 || !lowerHexSlice6(member.ID))) ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) {
		return phase6security.NetworkObservation{}, errors.New("formal Guest stage network declaration invalid")
	}
	declared := network
	activeIDs := map[string]string{}
	if member.State == "started" {
		activeIDs[network.Principals[0]] = member.ID
	} else {
		declared.Principals = nil
	}
	return phase6security.ObserveDockerNetworkWithExternal(raw, declared, activeIDs,
		map[string]string{"postgres": postgresID})
}

func slice6InspectGuestOperatorDialer(ctx context.Context, target slice6GuestOperatorTarget,
	principal phase6security.Principal, member slice6GuestPGMember) (string, []byte, error) {
	if ctx == nil || ctx.Err() != nil || principal.Name == "" || member.State != "started" ||
		len(member.ID) != 64 || !lowerHexSlice6(member.ID) ||
		!guestRevokeFixtureDigestGate(principal.ImageConfigDigest) {
		return "", nil, errors.New("formal Guest dialer inspect target invalid")
	}
	raw, err, overflow := slice6DockerBounded(ctx, 1024, nil, "inspect", "--format",
		"{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels \""+slice6RunLabel+"\"}}|"+
			"{{.State.Running}}|{{.State.ExitCode}}|{{.RestartCount}}|{{.State.Pid}}|{{.State.StartedAt}}", member.ID)
	if err != nil || overflow {
		clear(raw)
		return "", nil, errors.New("formal Guest dialer process unavailable")
	}
	digest, err := slice6CheckGuestOperatorDialerRaw(raw, target.Run.id, principal, member)
	if err != nil {
		clear(raw)
		return "", nil, err
	}
	return digest, raw, nil
}

func slice6CheckGuestOperatorDialerRaw(raw []byte, runID string,
	principal phase6security.Principal, member slice6GuestPGMember) (string, error) {
	if len(raw) < 10 || len(raw) > 1024 || raw[len(raw)-1] != '\n' ||
		len(runID) != 32 || !lowerHexSlice6(runID) ||
		principal.Name != "product-runtime" || principal.Kind != "runtime" ||
		member.State != "started" || len(member.ID) != 64 || !lowerHexSlice6(member.ID) {
		return "", errors.New("formal Guest dialer raw invalid")
	}
	parts := strings.Split(string(raw[:len(raw)-1]), "|")
	if len(parts) != 10 || parts[0] != member.ID ||
		parts[1] != "/sr-p6-"+principal.Name+"-"+runID ||
		parts[2] != principal.ImageDigest || parts[3] != principal.ImageReference ||
		parts[4] != runID || parts[7] != "0" {
		return "", errors.New("formal Guest dialer image/role identity drift")
	}
	started, startedErr := time.Parse(time.RFC3339Nano, parts[9])
	pid, pidErr := strconv.Atoi(parts[8])
	if startedErr != nil || started.IsZero() || pidErr != nil {
		return "", errors.New("formal Guest dialer lifecycle unavailable")
	}
	if principal.Kind != "runtime" || parts[5] != "true" || pid < 1 || pid > 1<<22 {
		return "", errors.New("formal Guest dialer not running")
	}
	return slice6ReceiptSHA256(raw), nil
}

func slice6ParseGuestOperatorRunInventory(raw []byte) (map[string]string, error) {
	if len(raw) < 2 || len(raw) > 64<<10 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("formal Guest operator inventory noncanonical")
	}
	result := make(map[string]string)
	for _, line := range strings.Split(string(raw[:len(raw)-1]), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 2 || len(fields[0]) != 64 || !lowerHexSlice6(fields[0]) ||
			fields[1] == "" || len(fields[1]) > 255 || result[fields[1]] != "" {
			return nil, errors.New("formal Guest operator inventory row invalid")
		}
		result[fields[1]] = fields[0]
	}
	return result, nil
}

type slice6GuestOperatorSettingsProof struct {
	ExecID, OutputDigest    string
	PostmasterStartMicros   int64
	RawOutput               []byte
	StartedUTC, FinishedUTC string
	ExitReceipt             []byte
}

func slice6VerifyGuestOperatorFinalPGSettings(ctx context.Context,
	target slice6GuestOperatorTarget) (string, error) {
	proof, err := slice6CheckGuestOperatorFinalPGSettings(ctx, target)
	clear(proof.RawOutput)
	clear(proof.ExitReceipt)
	return proof.ExecID, err
}

func slice6CheckGuestOperatorFinalPGSettings(ctx context.Context,
	target slice6GuestOperatorTarget) (slice6GuestOperatorSettingsProof, error) {
	if ctx == nil || ctx.Err() != nil || !target.valid() || !slice6GuestOperatorSQLMu.TryLock() {
		return slice6GuestOperatorSettingsProof{}, errors.New("formal Guest operator settings admission unavailable")
	}
	defer slice6GuestOperatorSQLMu.Unlock()
	if slice6GuestOperatorUncertain[target.Run.id] {
		return slice6GuestOperatorSettingsProof{}, errors.New("formal Guest operator prior SQL exit uncertain")
	}
	pidOne, err, overflow := slice6DockerBounded(ctx, 32, nil,
		"exec", "-u", "70:70", target.PostgresID, "cat", "/proc/1/comm")
	defer clear(pidOne)
	if err != nil || overflow || !bytes.Equal(pidOne, []byte("postgres\n")) {
		return slice6GuestOperatorSettingsProof{}, errors.New("formal Guest operator final PostgreSQL PID1 unavailable")
	}
	operation := make([]byte, 8)
	if _, err := rand.Read(operation); err != nil {
		return slice6GuestOperatorSettingsProof{}, errors.New("formal Guest operator settings operation unavailable")
	}
	appName := "sr-p6-proof-" + target.Run.id + "-" + hex.EncodeToString(operation)
	clear(operation)
	if len(appName) > 63 {
		return slice6GuestOperatorSettingsProof{}, errors.New("formal Guest operator settings application name invalid")
	}
	query := []byte(slice6GuestOperatorFinalSettingsSQL)
	exec, err := slice6RunGuestOperatorSQL(ctx, target.PostgresID, appName, query,
		[]string{"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
			"-h", "/var/run/postgresql", "-U", "postgres", "-d", "postgres", "-f", "-"}, 32)
	clear(query)
	defer clear(exec.Output)
	if err != nil || slice6CheckGuestOperatorExecExitReceipt(exec) != nil {
		slice6GuestOperatorUncertain[target.Run.id] = true
		slice6GuestOperatorUncertainExec[target.Run.id] = exec.ID
		return slice6GuestOperatorSettingsProof{}, errors.New("formal Guest operator settings SQL exit uncertain")
	}
	postmasterMicros, err := slice6ParseGuestOperatorSettingsOutput(exec.Output)
	if err != nil {
		return slice6GuestOperatorSettingsProof{}, err
	}
	return slice6GuestOperatorSettingsProof{ExecID: exec.ID,
		OutputDigest: slice6ReceiptSHA256(exec.Output), PostmasterStartMicros: postmasterMicros,
		RawOutput:  bytes.Clone(exec.Output),
		StartedUTC: exec.StartedUTC, FinishedUTC: exec.FinishedUTC,
		ExitReceipt: bytes.Clone(exec.ExitReceipt)}, nil
}

func slice6ParseGuestOperatorSettingsOutput(output []byte) (int64, error) {
	if len(output) < len("true|1577836800000000\n") || len(output) > 32 ||
		output[len(output)-1] != '\n' || bytes.Count(output, []byte{'\n'}) != 1 {
		return 0, errors.New("formal Guest operator settings output noncanonical")
	}
	parts := strings.Split(string(output[:len(output)-1]), "|")
	if len(parts) != 2 || parts[0] != "true" {
		return 0, errors.New("formal Guest operator final PostgreSQL settings drift")
	}
	postmasterMicros, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || strconv.FormatInt(postmasterMicros, 10) != parts[1] ||
		postmasterMicros < 1_577_836_800_000_000 || postmasterMicros > 4_102_444_800_000_000 {
		return 0, errors.New("formal Guest operator postmaster start invalid")
	}
	return postmasterMicros, nil
}

func slice6GuestOperatorNetworkRunLabel(raw []byte, runID string) bool {
	var values []struct {
		Labels map[string]string `json:"Labels"`
	}
	return json.Unmarshal(raw, &values) == nil && len(values) == 1 &&
		values[0].Labels[slice6RunLabel] == runID
}

func slice6GuestOperatorEndpointPresent(observed phase6security.NetworkObservation, id, ip string) bool {
	for _, endpoint := range observed.Endpoints {
		if endpoint.ContainerID == id && endpoint.IPv4Address == ip {
			return true
		}
	}
	return false
}

func slice6VerifyGuestOperatorMountedHBA(ctx context.Context, target slice6GuestOperatorTarget,
	expected []byte) error {
	mounted, err := slice6ReadGuestOperatorMountedHBA(ctx, target, expected)
	clear(mounted)
	return err
}

func slice6ReadGuestOperatorMountedHBA(ctx context.Context, target slice6GuestOperatorTarget,
	expected []byte) ([]byte, error) {
	mounted, err, overflow := slice6DockerBounded(ctx, 64<<10, nil,
		"exec", "-u", "70:70", target.PostgresID, "cat", "/pg/pg_hba.conf")
	if err != nil || overflow || !bytes.Equal(mounted, expected) {
		clear(mounted)
		return nil, errors.New("formal Guest operator mounted HBA drift")
	}
	return mounted, nil
}

func slice6VerifyGuestOperatorPGNetworkMap(ctx context.Context, target slice6GuestOperatorTarget,
	byName map[string]slice6PostgresEndpoint) error {
	raw, err, overflow := slice6DockerBounded(ctx, 16<<10, nil, "inspect", "--format",
		"{{json .NetworkSettings.Networks}}", target.PostgresID)
	defer clear(raw)
	if err != nil || overflow || len(raw) < 2 || len(raw) > 16<<10 {
		return errors.New("formal Guest operator PG network map unavailable")
	}
	var actual map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &actual) != nil || len(actual) != 9 {
		return errors.New("formal Guest operator PG network map invalid")
	}
	for name, network := range actual {
		endpoint, found := byName[name]
		if !found || endpoint.ID != network.NetworkID || endpoint.IP != network.IPAddress {
			return errors.New("formal Guest operator PG network endpoint drift")
		}
	}
	return nil
}

// The formal entry point has no strict/skip switch. Its source proof must be
// present and match the same live PG on both sides of the bounded SQL pair.
func slice6ReadGuestOperatorFormalPG(parent context.Context, target slice6GuestOperatorTarget,
	source slice6GuestOperatorFormalSource, expectedProfileDigest string, expectedHBA []byte,
	expectedState slice6GuestOperatorExpectedState, initialExpiryMicros int64) (slice6GuestOperatorReadback, error) {
	return slice6ReadGuestOperatorFormalPGRecorded(parent, target, source, expectedProfileDigest,
		expectedHBA, expectedState, initialExpiryMicros, "", nil)
}

func slice6GuestOperatorStage(expected slice6GuestOperatorExpectedState) string {
	switch expected {
	case slice6GuestOperatorInitialConnected:
		return "initial"
	case slice6GuestOperatorReleased:
		return "released"
	case slice6GuestOperatorRecoveredConnected:
		return "reconnected"
	case slice6GuestOperatorFinalReleased:
		return "final_released"
	default:
		return ""
	}
}

func slice6ReadGuestOperatorFormalPGRecorded(parent context.Context, target slice6GuestOperatorTarget,
	source slice6GuestOperatorFormalSource, expectedProfileDigest string, expectedHBA []byte,
	expectedState slice6GuestOperatorExpectedState, initialExpiryMicros int64,
	stage string, recorder *slice6GuestRecoveryERecorder) (slice6GuestOperatorReadback, error) {
	if recorder != nil && (stage != slice6GuestOperatorStage(expectedState) || recorder.runID != target.Run.id) {
		return slice6GuestOperatorReadback{}, errors.New("formal Guest operator E stage journal drift")
	}
	if parent == nil || parent.Err() != nil || !target.valid() ||
		source.runID != target.Run.id || source.postgresID != target.PostgresID ||
		source.imageRef != target.ImageRef || source.imageID != target.ImageID ||
		!guestRevokeFixtureDigestGate(expectedProfileDigest) ||
		source.profileDigest != expectedProfileDigest || source.pgFingerprint == "" ||
		!guestRevokeFixtureDigestGate(source.networkProofDigest) || len(source.endpoints) != 9 ||
		len(source.dialerIDs) != 9 ||
		!guestRevokeFixtureDigestGate(source.settingsOutputDigest) ||
		source.postmasterStartMicros < 1_577_836_800_000_000 ||
		len(source.settingsExecID) != 64 || !lowerHexSlice6(source.settingsExecID) ||
		source.hbaDigest != slice6ReceiptSHA256(expectedHBA) ||
		(expectedState != slice6GuestOperatorInitialConnected &&
			expectedState != slice6GuestOperatorReleased &&
			expectedState != slice6GuestOperatorRecoveredConnected &&
			expectedState != slice6GuestOperatorFinalReleased) ||
		(expectedState == slice6GuestOperatorInitialConnected && initialExpiryMicros != 0) ||
		(expectedState != slice6GuestOperatorInitialConnected &&
			(initialExpiryMicros < 1_577_836_800_000_000 || initialExpiryMicros > 4_102_444_800_000_000)) {
		return slice6GuestOperatorReadback{}, errors.New("formal Guest operator source proof missing")
	}
	frozenLedger, err := slice6FrozenProductMigrationLedger(parent)
	if err != nil {
		return slice6GuestOperatorReadback{}, err
	}
	if err := source.verifySourceSemantics(frozenLedger); err != nil {
		return slice6GuestOperatorReadback{}, err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	before, err := slice6InspectGuestOperatorPG(ctx, target)
	if err != nil || before != source.pgFingerprint ||
		slice6VerifyGuestOperatorMountedHBA(ctx, target, expectedHBA) != nil {
		return slice6GuestOperatorReadback{}, errors.New("formal Guest operator source changed before SQL")
	}
	readback, err := slice6ReadGuestOperatorPGRecorded(ctx, target, stage, source.proofDigest(), recorder)
	if err != nil {
		return slice6GuestOperatorReadback{}, err
	}
	preserveRaw := false
	defer func() {
		if !preserveRaw {
			clear(readback.RawRow)
			clear(readback.RawBackend)
			clear(readback.ReadExecExitRaw)
			clear(readback.CheckExecExitRaw)
			clear(readback.SettingsRecheckRaw)
			clear(readback.SettingsRecheckExitRaw)
		}
	}()
	if !readback.DBTimeUnexpired ||
		(initialExpiryMicros != 0 && readback.ExpiresUnixMicros != initialExpiryMicros) {
		return slice6GuestOperatorReadback{}, errors.New("formal Guest operator binding expiry drift")
	}
	switch expectedState {
	case slice6GuestOperatorInitialConnected, slice6GuestOperatorRecoveredConnected:
		if readback.State != "connected" || readback.NonceNull {
			return slice6GuestOperatorReadback{}, errors.New("formal Guest operator connected state unavailable")
		}
	case slice6GuestOperatorReleased, slice6GuestOperatorFinalReleased:
		if readback.State != "disconnected" || !readback.NonceNull {
			return slice6GuestOperatorReadback{}, errors.New("formal Guest operator released state unavailable")
		}
	default:
		return slice6GuestOperatorReadback{}, errors.New("formal Guest operator state unknown")
	}
	after, err := slice6InspectGuestOperatorPG(ctx, target)
	if err != nil || after != source.pgFingerprint ||
		slice6VerifyGuestOperatorMountedHBA(ctx, target, expectedHBA) != nil {
		return slice6GuestOperatorReadback{}, errors.New("formal Guest operator source changed after SQL")
	}
	recheck, err := slice6CheckGuestOperatorFinalPGSettings(ctx, target)
	defer clear(recheck.RawOutput)
	defer clear(recheck.ExitReceipt)
	if err != nil || recheck.ExecID == source.settingsExecID ||
		recheck.ExecID == readback.ReadExecID || recheck.ExecID == readback.CheckExecID ||
		recheck.OutputDigest != source.settingsOutputDigest ||
		recheck.PostmasterStartMicros != source.postmasterStartMicros {
		return slice6GuestOperatorReadback{}, errors.New("formal Guest operator effective settings/postmaster changed")
	}
	readback.PostgresFingerprint = source.pgFingerprint
	readback.ProfileDigest = source.profileDigest
	readback.SettingsRecheckExecID = recheck.ExecID
	readback.SettingsRecheckDigest = recheck.OutputDigest
	readback.PostmasterStartMicros = recheck.PostmasterStartMicros
	readback.SettingsRecheckRaw = bytes.Clone(recheck.RawOutput)
	readback.SettingsRecheckExitRaw = bytes.Clone(recheck.ExitReceipt)
	readback.SettingsRecheckStartedUTC = recheck.StartedUTC
	readback.SettingsRecheckFinishedUTC = recheck.FinishedUTC
	readback.SourceProofDigest = source.proofDigest()
	preserveRaw = true
	return readback, nil
}

// The recorded entry binds a real SQL call to the independently rechecked,
// persisted terminal readback. Failure leaves only the call event and an
// incomplete run; it cannot emit an observed success event.
func (run *slice6ReceiptEvidenceRun) captureGuestOperatorStageRecorded(parent context.Context,
	target slice6GuestOperatorTarget, source slice6GuestOperatorFormalSource,
	expectedProfileDigest string, expectedHBA []byte, expectedState slice6GuestOperatorExpectedState,
	initialExpiryMicros int64, recorder *slice6GuestRecoveryERecorder) (slice6GuestOperatorRawBinding, error) {
	if run == nil || run.check() != nil || source.evidence != run || recorder == nil ||
		recorder.runID != run.id {
		return slice6GuestOperatorRawBinding{}, errors.New("formal Guest E SQL capture unavailable")
	}
	stage := slice6GuestOperatorStage(expectedState)
	if stage == "" {
		return slice6GuestOperatorRawBinding{}, errors.New("formal Guest E SQL stage unavailable")
	}
	readback, err := slice6ReadGuestOperatorFormalPGRecorded(parent, target, source,
		expectedProfileDigest, expectedHBA, expectedState, initialExpiryMicros, stage, recorder)
	if err != nil {
		return slice6GuestOperatorRawBinding{}, err
	}
	defer func() {
		clear(readback.RawRow)
		clear(readback.RawBackend)
		clear(readback.ReadExecExitRaw)
		clear(readback.CheckExecExitRaw)
		clear(readback.SettingsRecheckRaw)
		clear(readback.SettingsRecheckExitRaw)
	}()
	binding, err := run.writeV2GuestOperatorRaw(stage, readback)
	if err != nil {
		return slice6GuestOperatorRawBinding{}, err
	}
	if recorder.record(slice6GuestRecoverySQLKind(stage, true), slice6GuestRecoverySQLRef(binding)) != nil {
		return slice6GuestOperatorRawBinding{}, errors.New("formal Guest E SQL terminal journal unavailable")
	}
	return binding, nil
}

func (source slice6GuestOperatorFormalSource) proofDigest() string {
	return slice6ReceiptSHA256([]byte("phase6-guest-formal-pg-source.v1|" +
		source.runID + "|" + source.postgresID + "|" + source.profileDigest + "|" +
		source.imageRef + "|" + source.imageID + "|" + source.pgFingerprint + "|" +
		source.hbaDigest + "|" + source.settingsExecID + "|" + source.settingsOutputDigest + "|" +
		strconv.FormatInt(source.postmasterStartMicros, 10) + "|" + source.networkProofDigest + "|" +
		source.rawProofDigest))
}

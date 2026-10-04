//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// Closed, same-run metadata is necessary to interpret the bounded raw files.
// It is source-derived at capture time; a digest inventory alone cannot
// reconstruct the nine-network phase or the removed migration lifecycle.
type slice6GuestOperatorSourceMetadata struct {
	Protocol, RunID, PostgresID, ProfileDigest string
	ImageRef, ImageID, PGFingerprint           string
	HBADigest, SettingsExecID                  string
	SettingsOutputDigest                       string
	SettingsStartedUTC, SettingsFinishedUTC    string
	PostmasterStartMicros                      int64
	NetworkProofDigest                         string
	Networks                                   []slice6GuestOperatorSourceNetwork
	Migration                                  slice6GuestOperatorSourceMigration
}

type slice6GuestOperatorSourceNetwork struct {
	Network                    phase6security.Network
	NetworkID, PostgresIP      string
	Dialer, DialerState        string
	DialerID, DialerIP         string
	PrincipalKind              string
	PrincipalImageRef          string
	PrincipalImageDigest       string
	PrincipalImageConfigDigest string
}

type slice6GuestOperatorSourceMigration struct {
	OriginalID, LedgerExecID            string
	LedgerStartedUTC, LedgerFinishedUTC string
	CurrentLedgerExecID                 string
	CurrentLedgerStartedUTC             string
	CurrentLedgerFinishedUTC            string
	ExpectedLedger                      []string
}

func (source slice6GuestOperatorFormalSource) verifySourceSemantics(expectedLedger []string) error {
	if phase6security.VerifySlice6DesiredFinalExternalProfile(source.profile) != nil ||
		source.profile.ProfileDigest != source.profileDigest {
		return errors.New("formal Guest source profile/raw unavailable")
	}
	expectedHBA, err := source.profile.PostgresServerAuth.RenderApprovedHBA(source.profile.ProviderDatabases)
	if err != nil {
		return errors.New("formal Guest source frozen HBA unavailable")
	}
	defer clear(expectedHBA)
	return source.verifySourceSemanticsCore(expectedLedger, expectedHBA)
}

// Core only interprets already-frozen source inputs. The formal caller above
// must validate the complete Profile before entry; pure tests can construct a
// smaller synthetic source graph without claiming a deployable Profile.
func (source slice6GuestOperatorFormalSource) verifySourceSemanticsCore(expectedLedger []string,
	expectedHBA []byte) error {
	if source.verifyRawFiles() != nil || source.profile.ProfileDigest != source.profileDigest {
		return errors.New("formal Guest source raw inventory unavailable")
	}
	metadataRaw, err := source.evidence.readFile("guest-source-metadata.json", 32<<10)
	if err != nil {
		return errors.New("formal Guest source metadata unavailable")
	}
	defer clear(metadataRaw)
	var meta slice6GuestOperatorSourceMetadata
	if json.Unmarshal(metadataRaw, &meta) != nil {
		return errors.New("formal Guest source metadata invalid")
	}
	canonical, err := json.Marshal(meta)
	if err != nil || !bytes.Equal(metadataRaw, canonical) ||
		meta.Protocol != "sandbox-runtime.phase6-guest-source.v1" ||
		meta.RunID != source.runID || meta.PostgresID != source.postgresID ||
		meta.ProfileDigest != source.profileDigest || meta.ImageRef != source.imageRef ||
		meta.ImageID != source.imageID || meta.PGFingerprint != source.pgFingerprint ||
		meta.HBADigest != source.hbaDigest || meta.SettingsExecID != source.settingsExecID ||
		meta.SettingsOutputDigest != source.settingsOutputDigest ||
		meta.SettingsStartedUTC != source.settingsExecStartedUTC ||
		meta.SettingsFinishedUTC != source.settingsExecFinishedUTC ||
		meta.PostmasterStartMicros != source.postmasterStartMicros ||
		meta.NetworkProofDigest != source.networkProofDigest || len(meta.Networks) != 9 {
		return errors.New("formal Guest source metadata binding drift")
	}
	read := func(name string) ([]byte, error) {
		return source.evidence.readFile(name, slice6GuestOperatorSourceRawLimit(name))
	}
	hba, err := read("guest-source-hba.raw")
	if err != nil {
		return err
	}
	defer clear(hba)
	if !bytes.Equal(hba, expectedHBA) || slice6ReceiptSHA256(hba) != meta.HBADigest {
		return errors.New("formal Guest mounted HBA raw/profile drift")
	}
	settings, err := read("guest-source-settings.stdout")
	if err != nil {
		return err
	}
	defer clear(settings)
	settingsExit, err := read("guest-source-settings-exit.receipt")
	if err != nil {
		return err
	}
	defer clear(settingsExit)
	micros, err := slice6ParseGuestOperatorSettingsOutput(settings)
	if err != nil || micros != meta.PostmasterStartMicros ||
		slice6ReceiptSHA256(settings) != meta.SettingsOutputDigest ||
		slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: meta.SettingsExecID,
			ContainerID: meta.PostgresID, StartedUTC: meta.SettingsStartedUTC,
			FinishedUTC: meta.SettingsFinishedUTC, ExitReceipt: settingsExit}) != nil {
		return errors.New("formal Guest settings raw/exec drift")
	}
	inventoryRaw, err := read("guest-source-container-inventory.stdout")
	if err != nil {
		return err
	}
	defer clear(inventoryRaw)
	inventory, err := slice6ParseGuestOperatorRunInventory(inventoryRaw)
	if err != nil || inventory["sr-p6-postgres-"+meta.RunID] != meta.PostgresID {
		return errors.New("formal Guest inventory raw drift")
	}
	postgresRaw, err := read("guest-source-postgres.inspect")
	if err != nil {
		return err
	}
	defer clear(postgresRaw)
	pgDigest, err := slice6CheckGuestOperatorPGRaw(postgresRaw, meta.RunID,
		meta.PostgresID, meta.ImageID, meta.ImageRef)
	if err != nil || pgDigest != meta.PGFingerprint {
		return errors.New("formal Guest PostgreSQL PID1/image/mount raw drift")
	}
	pgParts := strings.Split(strings.TrimSuffix(string(postgresRaw), "\n"), "|")
	var pgNetworks map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}
	if len(pgParts) != 13 || json.Unmarshal([]byte(pgParts[12]), &pgNetworks) != nil || len(pgNetworks) != 9 {
		return errors.New("formal Guest PostgreSQL nine-network raw map drift")
	}
	principalByName := make(map[string]phase6security.Principal)
	for _, principal := range source.profile.Principals {
		principalByName[principal.Name] = principal
	}
	profileNetworks := make(map[string]phase6security.Network)
	for _, network := range source.profile.Networks {
		profileNetworks[network.Name] = network
	}
	productNetworksRaw, err := read("guest-source-product-networks.inspect")
	if err != nil {
		return err
	}
	defer clear(productNetworksRaw)
	productID := source.dialerIDs["service-product-postgres"]
	productNetworks, err := slice6ParseGuestSourceProductNetworks(productNetworksRaw, meta.RunID, productID)
	if err != nil || len(productNetworks) < 2 ||
		productNetworks["service-product-postgres"].NetworkID != source.endpoints["service-product-postgres"].ID ||
		len(productNetworks["guest-product"].NetworkID) != 64 ||
		!lowerHexSlice6(productNetworks["guest-product"].NetworkID) {
		return errors.New("formal Guest Product retained-network raw drift")
	}
	for name, endpoint := range productNetworks {
		if !slices.Contains(profileNetworks[name].Principals, "product-runtime") {
			return errors.New("formal Guest Product network outside frozen Profile")
		}
		expectedIP, addressErr := phase6security.Slice6DesiredEndpointAddress(name, "product-runtime")
		if addressErr != nil {
			expectedIP, addressErr = phase6security.Slice6DesiredFinalServiceEndpointAddress(name, "product-runtime")
		}
		if addressErr != nil || endpoint.IPAddress != expectedIP {
			return errors.New("formal Guest Product network endpoint/profile drift")
		}
	}
	proofLines := make([]string, 0, 9)
	seen := make(map[string]bool)
	var migrationSeen bool
	index := 0
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service != "postgres" {
			continue
		}
		entry := meta.Networks[index]
		index++
		principal := principalByName[path.Dialer]
		wantedNetwork := profileNetworks[path.Network]
		pgIP, pgErr := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, "postgres")
		peerIP, peerErr := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, path.Dialer)
		if pgErr != nil || peerErr != nil || seen[path.Network] ||
			entry.Network.Name != path.Network || !reflect.DeepEqual(entry.Network, wantedNetwork) ||
			entry.Dialer != path.Dialer || entry.DialerState != slice6GuestOperatorAStageState(path.Dialer) ||
			entry.PostgresIP != pgIP || entry.DialerIP != peerIP ||
			entry.PrincipalKind != principal.Kind || entry.PrincipalImageRef != principal.ImageReference ||
			entry.PrincipalImageDigest != principal.ImageDigest ||
			entry.PrincipalImageConfigDigest != principal.ImageConfigDigest ||
			len(entry.NetworkID) != 64 || !lowerHexSlice6(entry.NetworkID) ||
			entry.NetworkID != source.endpoints[path.Network].ID ||
			entry.PostgresIP != source.endpoints[path.Network].IP ||
			entry.DialerID != source.dialerIDs[path.Network] {
			return errors.New("formal Guest source network metadata/profile drift")
		}
		if pgNetworks[path.Network].NetworkID != entry.NetworkID ||
			pgNetworks[path.Network].IPAddress != entry.PostgresIP {
			return errors.New("formal Guest PostgreSQL source endpoint raw drift")
		}
		seen[path.Network] = true
		member := slice6GuestPGMember{State: entry.DialerState, ID: entry.DialerID}
		networkRaw, err := read("guest-source-network-" + path.Network + ".json")
		if err != nil {
			return err
		}
		if !slice6GuestOperatorNetworkRunLabel(networkRaw, meta.RunID) {
			clear(networkRaw)
			return errors.New("formal Guest network raw run label drift")
		}
		observed, observeErr := slice6ObserveGuestOperatorPGStageNetwork(networkRaw,
			entry.Network, member, meta.PostgresID)
		clear(networkRaw)
		if observeErr != nil || observed.NetworkID != entry.NetworkID ||
			!slice6GuestOperatorEndpointPresent(observed, meta.PostgresID, entry.PostgresIP) {
			return errors.New("formal Guest network raw membership drift")
		}
		memberProof := "not-started"
		switch entry.DialerState {
		case "started":
			if inventory["sr-p6-product-runtime-"+meta.RunID] != entry.DialerID ||
				!slice6GuestOperatorEndpointPresent(observed, entry.DialerID, entry.DialerIP) {
				return errors.New("formal Guest started dialer raw drift")
			}
			dialerRaw, readErr := read("guest-source-product-runtime.inspect")
			if readErr != nil {
				return readErr
			}
			memberProof, err = slice6CheckGuestOperatorDialerRaw(dialerRaw, meta.RunID, principal, member)
			clear(dialerRaw)
			if err != nil {
				return err
			}
		case "migrated_exited_removed":
			if migrationSeen {
				return errors.New("formal Guest migration raw replay")
			}
			migrationSeen = true
			memberProof, err = source.verifyMigrationRaw(meta, principal, inventoryRaw, expectedLedger)
			if err != nil || meta.Migration.OriginalID != entry.DialerID {
				return errors.New("formal Guest migration raw drift")
			}
		case "not_started":
			if entry.DialerID != "" || inventory["sr-p6-"+path.Dialer+"-"+meta.RunID] != "" {
				return errors.New("formal Guest not-started dialer appeared")
			}
		default:
			return errors.New("formal Guest unknown phase")
		}
		proofLines = append(proofLines, path.Network+"|"+entry.NetworkID+"|"+entry.PostgresIP+"|"+
			entry.DialerState+"|"+entry.DialerID+"|"+entry.DialerIP+"|"+
			principal.ImageConfigDigest+"|"+memberProof+"|"+observed.InspectDigest)
	}
	if len(seen) != 9 || !migrationSeen {
		return errors.New("formal Guest source phase inventory incomplete")
	}
	slices.Sort(proofLines)
	if meta.NetworkProofDigest != slice6ReceiptSHA256([]byte(strings.Join(proofLines, "\n"))) {
		return errors.New("formal Guest network proof not reconstructable from raw")
	}
	return nil
}

func (source slice6GuestOperatorFormalSource) verifyMigrationRaw(meta slice6GuestOperatorSourceMetadata,
	principal phase6security.Principal, inventoryRaw []byte, expectedLedger []string) (string, error) {
	read := func(name string) ([]byte, error) {
		return source.evidence.readFile(name, slice6GuestOperatorSourceRawLimit(name))
	}
	names := slice6ProductMigrationProofRawNames()
	parts := make(map[string][]byte, len(names))
	defer func() {
		for _, raw := range parts {
			clear(raw)
		}
	}()
	for _, name := range names {
		raw, err := read(name)
		if err != nil {
			return "", err
		}
		parts[name] = raw
	}
	m := meta.Migration
	if len(m.ExpectedLedger) != len(slice6ProductMigrationFiles) ||
		len(expectedLedger) != len(slice6ProductMigrationFiles) ||
		!slices.Equal(m.ExpectedLedger, expectedLedger) ||
		m.OriginalID == "" || m.CurrentLedgerExecID == m.LedgerExecID ||
		!bytes.Equal(parts["product-migration-current-ledger.stdout"], parts["product-migration-ledger.stdout"]) {
		return "", errors.New("formal Guest migration expected/current ledger drift")
	}
	proof := slice6ProductMigrationExitProof{RunID: meta.RunID, ContainerID: m.OriginalID,
		PostgresID: meta.PostgresID, ExitRaw: parts["product-migration-exit.inspect"],
		LedgerRaw:         parts["product-migration-ledger.stdout"],
		RemovalRaw:        parts["product-migration-remove.stdout"],
		LedgerExecExitRaw: parts["product-migration-ledger-exit.receipt"],
		LedgerExecID:      m.LedgerExecID, LedgerStartedUTC: m.LedgerStartedUTC,
		LedgerFinishedUTC: m.LedgerFinishedUTC}
	originalDigest, err := slice6CheckProductMigrationExitProof(proof, principal, expectedLedger)
	if err != nil {
		return "", err
	}
	listed, err := slice6ParseGuestOperatorRunInventory(inventoryRaw)
	if err != nil || listed["sr-p6-product-migrate-live-"+meta.RunID] != "" {
		return "", errors.New("formal Guest migration original name reappeared")
	}
	for _, id := range listed {
		if id == m.OriginalID {
			return "", errors.New("formal Guest migration original ID reappeared")
		}
	}
	if slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: m.CurrentLedgerExecID,
		ContainerID: meta.PostgresID, StartedUTC: m.CurrentLedgerStartedUTC,
		FinishedUTC: m.CurrentLedgerFinishedUTC,
		ExitReceipt: parts["product-migration-current-ledger-exit.receipt"]}) != nil {
		return "", errors.New("formal Guest migration current ledger exec drift")
	}
	return slice6ReceiptSHA256([]byte(originalDigest + "|" + slice6ReceiptSHA256(inventoryRaw) + "|" +
		m.CurrentLedgerExecID + "|" + slice6ReceiptSHA256(parts["product-migration-current-ledger.stdout"]) + "|" +
		slice6ReceiptSHA256(parts["product-migration-current-ledger-exit.receipt"]) + "|" +
		strconv.Itoa(len(expectedLedger)))), nil
}

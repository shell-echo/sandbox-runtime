//go:build phase6slice6gate

package productphase6gate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestSlice6GuestSourceRawReconstructsNineNetworkProof(t *testing.T) {
	for _, variant := range []string{"frozen-ledger", "metadata-and-two-ledgers-self-consistent-but-not-frozen",
		"self-consistent-network-digest-drift", "self-consistent-PG-fingerprint-drift"} {
		t.Run(variant, func(t *testing.T) {
			rootPath := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(rootPath, 0o700); err != nil {
				t.Fatal(err)
			}
			rootPath, err := filepath.EvalSymlinks(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			root, err := slice6OpenReceiptEvidenceRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.close()
			runID := strings.Repeat("a", 32)
			run, err := root.newRun(runID)
			if err != nil {
				t.Fatal(err)
			}
			defer run.close()
			pgID, productID, migrationID := strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
			pgImage := "sha256:" + strings.Repeat("e", 64)
			pgRef := "postgres:16-alpine@sha256:" + strings.Repeat("e", 64)
			coreImage := "sha256:" + strings.Repeat("f", 64)
			profileDigest := "sha256:" + strings.Repeat("2", 64)
			settingsID, migrationExecID, currentExecID := strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64)
			base := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
			stamp := func(s int) string { return base.Add(time.Duration(s) * time.Second).Format(time.RFC3339Nano) }
			hba, err := phase6security.RenderSlice6DesiredFinalSharedPostgresHBA()
			if err != nil {
				t.Fatal(err)
			}
			settingsRaw := []byte("true|1791080000000000\n")
			inventoryRaw := []byte(pgID + "|sr-p6-postgres-" + runID + "\n" +
				productID + "|sr-p6-product-runtime-" + runID + "\n")
			frozenLedger := make([]string, len(slice6ProductMigrationFiles))
			for index := range frozenLedger {
				frozenLedger[index] = fmt.Sprintf("%d|sha256:%s", index+1, strings.Repeat("6", 64))
			}
			observedLedger := slices.Clone(frozenLedger)
			if variant == "metadata-and-two-ledgers-self-consistent-but-not-frozen" {
				observedLedger[0] = "1|sha256:" + strings.Repeat("7", 64)
			}
			ledgerRaw := []byte(strings.Join(observedLedger, "\n") + "\n")
			migration := slice6ProductMigrationExitProof{RunID: runID, ContainerID: migrationID, PostgresID: pgID,
				ExitRaw: []byte(migrationID + "|/sr-p6-product-migrate-live-" + runID + "|" + coreImage + "|" +
					coreImage + "|" + runID + "|false|0|false|0|0|" + stamp(0) + "|" + stamp(1) + "\n"),
				LedgerRaw: ledgerRaw, RemovalRaw: []byte(migrationID + "\n"),
				LedgerExecID: migrationExecID, LedgerStartedUTC: stamp(2), LedgerFinishedUTC: stamp(3),
				LedgerExecExitRaw: slice6GuestOperatorExecExitReceipt(migrationExecID, pgID, stamp(3))}
			productRaw := []byte(productID + "|/sr-p6-product-runtime-" + runID + "|" + coreImage + "|" +
				coreImage + "|" + runID + "|true|0|0|123|" + stamp(4) + "\n")
			profile := phase6security.Profile{ProfileDigest: profileDigest}
			meta := slice6GuestOperatorSourceMetadata{Protocol: "sandbox-runtime.phase6-guest-source.v1",
				RunID: runID, PostgresID: pgID, ProfileDigest: profileDigest,
				ImageRef: pgRef, ImageID: pgImage,
				HBADigest: slice6ReceiptSHA256(hba), SettingsExecID: settingsID,
				SettingsOutputDigest: slice6ReceiptSHA256(settingsRaw),
				SettingsStartedUTC:   stamp(5), SettingsFinishedUTC: stamp(6),
				PostmasterStartMicros: 1791080000000000,
				Migration: slice6GuestOperatorSourceMigration{OriginalID: migrationID,
					LedgerExecID: migrationExecID, LedgerStartedUTC: stamp(2), LedgerFinishedUTC: stamp(3),
					CurrentLedgerExecID: currentExecID, CurrentLedgerStartedUTC: stamp(7),
					CurrentLedgerFinishedUTC: stamp(8), ExpectedLedger: observedLedger}}
			rawFiles := make(map[string]string)
			write := func(name string, raw []byte) {
				t.Helper()
				digest, err := run.writeV2GuestSourceRaw(name, raw)
				if err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
				rawFiles[name] = digest
			}
			write("guest-source-hba.raw", hba)
			write("guest-source-settings.stdout", settingsRaw)
			write("guest-source-settings-exit.receipt",
				slice6GuestOperatorExecExitReceipt(settingsID, pgID, stamp(6)))
			write("guest-source-container-inventory.stdout", inventoryRaw)
			write("guest-source-product-runtime.inspect", productRaw)
			write("product-migration-exit.inspect", migration.ExitRaw)
			write("product-migration-ledger.stdout", migration.LedgerRaw)
			write("product-migration-remove.stdout", migration.RemovalRaw)
			write("product-migration-ledger-exit.receipt", migration.LedgerExecExitRaw)
			write("product-migration-current-ledger.stdout", ledgerRaw)
			currentReceipt := slice6GuestOperatorExecExitReceipt(currentExecID, pgID, stamp(8))
			write("product-migration-current-ledger-exit.receipt", currentReceipt)
			pgNetworks := make(map[string]map[string]string)
			endpoints := make(map[string]slice6PostgresEndpoint)
			dialerIDs := make(map[string]string)
			var proofLines []string
			pathIndex := 0
			for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
				if path.Service != "postgres" {
					continue
				}
				var network phase6security.Network
				for _, candidate := range phase6security.Slice6DesiredFinalServiceBridges() {
					if candidate.Name == path.Network {
						network = candidate
					}
				}
				if network.Name == "" {
					t.Fatal("missing desired PG network")
				}
				pgIP, err := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, "postgres")
				if err != nil {
					t.Fatal(err)
				}
				peerIP, err := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, path.Dialer)
				if err != nil {
					t.Fatal(err)
				}
				state := slice6GuestOperatorAStageState(path.Dialer)
				peerID := ""
				if state == "started" {
					peerID = productID
				} else if state == "migrated_exited_removed" {
					peerID = migrationID
				}
				networkID := fmt.Sprintf("%064x", pathIndex+1)
				pathIndex++
				principal := phase6security.Principal{Name: path.Dialer, Kind: "runtime",
					ImageReference: coreImage, ImageDigest: coreImage,
					ImageConfigDigest: "sha256:" + strings.Repeat("1", 64)}
				if state == "migrated_exited_removed" || strings.Contains(path.Dialer, "migration-job") {
					principal.Kind = "migration_job"
				}
				profile.Principals = append(profile.Principals, principal)
				profile.Networks = append(profile.Networks, network)
				pgNetworks[path.Network] = map[string]string{"NetworkID": networkID, "IPAddress": pgIP}
				containers := map[string]map[string]string{pgID: {"IPv4Address": pgIP + "/24"}}
				if state == "started" {
					containers[productID] = map[string]string{"IPv4Address": peerIP + "/24"}
				}
				networkRaw, err := json.Marshal([]any{map[string]any{
					"Name": network.Name, "Id": networkID, "Driver": "bridge", "Scope": "local",
					"Internal": true, "Attachable": false, "Ingress": false,
					"EnableIPv4": true, "EnableIPv6": false,
					"Labels": map[string]string{slice6RunLabel: runID},
					"Options": map[string]string{
						"com.docker.network.bridge.gateway_mode_ipv4": "isolated",
						"com.docker.network.enable_ipv4":              "true", "com.docker.network.enable_ipv6": "false"},
					"IPAM":       map[string]any{"Config": []map[string]string{{"Subnet": network.IPv4Subnet, "Gateway": ""}}},
					"Containers": containers,
				}})
				if err != nil {
					t.Fatal(err)
				}
				write("guest-source-network-"+path.Network+".json", networkRaw)
				member := slice6GuestPGMember{State: state, ID: peerID}
				observed, err := slice6ObserveGuestOperatorPGStageNetwork(networkRaw, network, member, pgID)
				if err != nil {
					t.Fatal(err)
				}
				memberProof := "not-started"
				if state == "started" {
					memberProof = slice6ReceiptSHA256(productRaw)
				} else if state == "migrated_exited_removed" {
					original, err := slice6CheckProductMigrationExitProof(migration, principal, observedLedger)
					if err != nil {
						t.Fatal(err)
					}
					memberProof = slice6ReceiptSHA256([]byte(original + "|" + slice6ReceiptSHA256(inventoryRaw) + "|" +
						currentExecID + "|" + slice6ReceiptSHA256(ledgerRaw) + "|" +
						slice6ReceiptSHA256(currentReceipt) + "|" + fmt.Sprint(len(observedLedger))))
				}
				meta.Networks = append(meta.Networks, slice6GuestOperatorSourceNetwork{
					Network: network, NetworkID: networkID, PostgresIP: pgIP,
					Dialer: path.Dialer, DialerState: state, DialerID: peerID, DialerIP: peerIP,
					PrincipalKind: principal.Kind, PrincipalImageRef: principal.ImageReference,
					PrincipalImageDigest:       principal.ImageDigest,
					PrincipalImageConfigDigest: principal.ImageConfigDigest})
				proofLines = append(proofLines, path.Network+"|"+networkID+"|"+pgIP+"|"+state+"|"+
					peerID+"|"+peerIP+"|"+principal.ImageConfigDigest+"|"+memberProof+"|"+observed.InspectDigest)
				endpoints[path.Network] = slice6PostgresEndpoint{Network: network, ID: networkID, IP: pgIP}
				dialerIDs[path.Network] = peerID
			}
			pgNetworksRaw, err := json.Marshal(pgNetworks)
			if err != nil {
				t.Fatal(err)
			}
			productPGIP, err := phase6security.Slice6DesiredFinalServiceEndpointAddress("service-product-postgres", "product-runtime")
			if err != nil {
				t.Fatal(err)
			}
			productGuestIP, err := phase6security.Slice6DesiredEndpointAddress("guest-product", "product-runtime")
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range phase6security.Slice6DesiredNetworks() {
				if candidate.Name == "guest-product" {
					profile.Networks = append(profile.Networks, candidate)
				}
			}
			productNetworkRaw := []byte(productID + "|" + runID + "\nguest-product|" +
				strings.Repeat("6", 64) + "|" + productGuestIP + "\nservice-product-postgres|" +
				endpoints["service-product-postgres"].ID + "|" + productPGIP + "\n")
			write("guest-source-product-networks.inspect", productNetworkRaw)
			pgRaw := []byte(pgID + "|/sr-p6-postgres-" + runID + "|" + pgImage + "|" + pgRef +
				"|70:70|" + runID + "|true|321|" + stamp(0) + "|false|0|" +
				"volume@sr-p6-postgres-config-" + runID + "@/pg@false," +
				"volume@sr-p6-postgres-data-" + runID + "@/var/lib/postgresql/data@true,|" +
				string(pgNetworksRaw) + "\n")
			pgFingerprint, err := slice6CheckGuestOperatorPGRaw(pgRaw, runID, pgID, pgImage, pgRef)
			if err != nil {
				t.Fatal(err)
			}
			write("guest-source-postgres.inspect", pgRaw)
			profile.Principals = append(profile.Principals, phase6security.Principal{
				Name: "guest-runtime", Kind: "runtime", ImageReference: coreImage,
				ImageDigest: coreImage, ImageConfigDigest: "sha256:" + strings.Repeat("1", 64)})
			slices.Sort(proofLines)
			meta.PGFingerprint = pgFingerprint
			meta.NetworkProofDigest = slice6ReceiptSHA256([]byte(strings.Join(proofLines, "\n")))
			if variant == "self-consistent-network-digest-drift" {
				meta.NetworkProofDigest = slice6ReceiptSHA256([]byte("wrong-network-proof"))
			}
			if variant == "self-consistent-PG-fingerprint-drift" {
				meta.PGFingerprint = slice6ReceiptSHA256([]byte("wrong-PG-fingerprint"))
			}
			metaRaw, err := json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
			write("guest-source-metadata.json", metaRaw)
			source := slice6GuestOperatorFormalSource{runID: runID, postgresID: pgID,
				profileDigest: profileDigest, imageRef: pgRef, imageID: pgImage,
				pgFingerprint: pgFingerprint, hbaDigest: meta.HBADigest,
				settingsExecID: settingsID, settingsOutputDigest: meta.SettingsOutputDigest,
				settingsExecStartedUTC:  meta.SettingsStartedUTC,
				settingsExecFinishedUTC: meta.SettingsFinishedUTC,
				postmasterStartMicros:   meta.PostmasterStartMicros,
				networkProofDigest:      meta.NetworkProofDigest,
				rawFiles:                rawFiles, rawProofDigest: slice6GuestOperatorRawProofDigest(rawFiles),
				evidence: run, profile: profile, endpoints: endpoints, dialerIDs: dialerIDs}
			err = source.verifySourceSemanticsCore(frozenLedger, hba)
			if variant != "frozen-ledger" {
				if err == nil {
					t.Fatal("self-consistent source metadata drift accepted")
				}
			} else if err != nil {
				t.Fatalf("synthetic complete source raw did not reconstruct: %v", err)
			} else {
				slice6SyntheticGuestRecoveryPrecleanup(t, run, source, base, productID, pgID)
			}
		})
	}
}

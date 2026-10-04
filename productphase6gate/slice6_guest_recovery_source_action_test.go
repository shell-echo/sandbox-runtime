//go:build phase6slice6gate

package productphase6gate

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// Bind facts available in the independently saved A′ source to E actions.
// This does not replace missing raw before/after action observations or a
// monotonic E event ledger; the formal gate must still require those.
func slice6VerifyGuestRecoveryActionSourceIdentity(source slice6GuestOperatorFormalSource,
	ledger slice6GuestRecoveryActionLedger, process [4]slice6GuestRecoveryRawBinding,
	sql [4]slice6GuestOperatorRawBinding) error {
	if source.verifyRawFiles() != nil || source.evidence == nil {
		return errors.New("Guest recovery action source raw unavailable")
	}
	productRaw, err := source.evidence.readFile("guest-source-product-runtime.inspect", 1024)
	if err != nil {
		return err
	}
	defer clear(productRaw)
	product := strings.Split(strings.TrimSuffix(string(productRaw), "\n"), "|")
	if len(product) != 10 || product[0] != process[0].ContainerID ||
		product[8] != strconv.Itoa(process[0].PID) || product[9] != process[0].StartedAt ||
		ledger.PGDown.ProductPID != process[0].PID ||
		ledger.PGDown.ProductStartedAt != process[0].StartedAt {
		return errors.New("Guest recovery Product-A source/PID1 identity drift")
	}
	pgRaw, err := source.evidence.readFile("guest-source-postgres.inspect", 16<<10)
	if err != nil {
		return err
	}
	defer clear(pgRaw)
	pg := strings.Split(strings.TrimSuffix(string(pgRaw), "\n"), "|")
	if len(pg) != 13 || pg[0] != source.postgresID || pg[6] != "true" ||
		pg[8] != ledger.PGDown.PostgresStartedAt {
		return errors.New("Guest recovery PostgreSQL source identity drift")
	}
	// PostgreSQL raw projection fields are ID,name,image,ref,user,label,
	// running,PID,start,restart,exit,mounts,networks.
	pgPID, parseErr := strconv.Atoi(pg[7])
	if parseErr != nil || pgPID < 1 || pgPID != ledger.PGDown.PostgresPID {
		return errors.New("Guest recovery PostgreSQL source PID drift")
	}
	var pgNetworks map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}
	if json.Unmarshal([]byte(pg[12]), &pgNetworks) != nil || len(pgNetworks) != 9 ||
		ledger.PGDown.NetworkID != pgNetworks["service-product-postgres"].NetworkID ||
		ledger.PGDown.NetworkID != source.endpoints["service-product-postgres"].ID ||
		ledger.PGDown.PostgresNetworks != slice6ProductPGNetworkDigest(pgNetworks, "") {
		return errors.New("Guest recovery PostgreSQL source network drift")
	}
	productNetworksRaw, err := source.evidence.readFile("guest-source-product-networks.inspect", 4096)
	if err != nil {
		return err
	}
	defer clear(productNetworksRaw)
	productNetworks, err := slice6ParseGuestSourceProductNetworks(productNetworksRaw, source.runID, process[0].ContainerID)
	if err != nil || productNetworks["service-product-postgres"].NetworkID != ledger.PGDown.NetworkID ||
		ledger.PGDown.ProductOtherNetworks != slice6ProductPGNetworkDigest(productNetworks, "service-product-postgres") ||
		productNetworks["guest-product"].NetworkID != ledger.GuestOff.ProductNetworkID {
		return errors.New("Guest recovery Product retained-network source drift")
	}
	pgBefore := strings.Split(ledger.PGDown.BeforeProjection, "|")
	if len(pgBefore) != 13 || pgBefore[8] != productNetworks["service-product-postgres"].IPAddress ||
		pgBefore[9] != pgNetworks["service-product-postgres"].IPAddress {
		return errors.New("Guest recovery Product/PostgreSQL endpoint projection drift")
	}
	guestBefore := strings.Split(ledger.GuestOff.BeforeProjection, "|")
	if len(guestBefore) != 13 || guestBefore[8] != productNetworks["guest-product"].IPAddress ||
		guestBefore[7] != productNetworks["guest-product"].NetworkID {
		return errors.New("Guest recovery Product/Guest endpoint projection drift")
	}
	guestIP, guestErr := phase6security.Slice6DesiredEndpointAddress("guest-product", "guest-runtime")
	runtimeIP, runtimeErr := phase6security.Slice6DesiredEndpointAddress("network-guest-runtime", "guest-runtime")
	if guestErr != nil || runtimeErr != nil || ledger.GuestOff.GuestIP != guestIP ||
		ledger.GuestOff.RuntimeIP != runtimeIP {
		return errors.New("Guest recovery frozen Guest endpoint drift")
	}
	settingsFinished, settingsErr := time.Parse(time.RFC3339Nano, source.settingsExecFinishedUTC)
	initialSQL, sqlErr := time.Parse(time.RFC3339Nano, sql[0].ReadStartedUTC)
	if settingsErr != nil || sqlErr != nil || !initialSQL.After(settingsFinished) {
		return errors.New("Guest recovery A′ source completed after initial SQL")
	}
	return nil
}

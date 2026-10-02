package phase6security

import "errors"

// Slice6VaultRoleBackdateSeconds is the exact not_before_duration installed
// and read back for every Slice 6 Vault PKI role. It is not a caller option.
const Slice6VaultRoleBackdateSeconds int64 = 30

const slice6CertificateTimeReserveSeconds int64 = 1

// Slice6ManagedCertificateRequestTTL keeps Vault's backdated X.509 interval
// inside the Profile's total-lifetime ceiling. The extra second is a
// conservative timestamp-granularity budget, not an observed Vault guarantee.
// A too-short Profile or rotation window fails closed instead of being clamped.
func Slice6ManagedCertificateRequestTTL(profileMaxSeconds, rotateAfterSeconds int64) (int64, error) {
	if profileMaxSeconds < 60 || profileMaxSeconds > 3600 ||
		rotateAfterSeconds < 1 || rotateAfterSeconds > profileMaxSeconds*2/3 {
		return 0, errors.New("invalid Slice 6 certificate lifetime budget")
	}
	requested := profileMaxSeconds - Slice6VaultRoleBackdateSeconds - slice6CertificateTimeReserveSeconds
	if requested < 60 || rotateAfterSeconds > requested*2/3 {
		return 0, errors.New("Slice 6 certificate lifetime budget cannot fit Vault backdate and rotation")
	}
	return requested, nil
}

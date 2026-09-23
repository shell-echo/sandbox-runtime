package providerapi

import (
	"crypto/tls"
	"errors"
)

// cloneStrictProviderMTLS admits the historical single frozen certificate or
// the exclusive live signer used by the profile-bound production graph. No
// client-hello callback may replace the complete transport policy.
func cloneStrictProviderMTLS(source *tls.Config) (*tls.Config, error) {
	if source == nil {
		return nil, errors.New("Provider mTLS configuration is required")
	}
	staticIdentity := len(source.Certificates) == 1 && source.GetCertificate == nil
	liveIdentity := len(source.Certificates) == 0 && source.GetCertificate != nil && source.SessionTicketsDisabled
	if source.MinVersion != tls.VersionTLS13 || source.MaxVersion != tls.VersionTLS13 ||
		(!staticIdentity && !liveIdentity) || source.ClientAuth != tls.RequireAndVerifyClientCert ||
		source.ClientCAs == nil || source.VerifyConnection == nil ||
		source.GetConfigForClient != nil || source.GetClientCertificate != nil || source.VerifyPeerCertificate != nil {
		return nil, errors.New("Provider mTLS configuration is invalid")
	}
	return source.Clone(), nil
}

// bindProviderClientAdmission keeps the transport callback's exact
// profile-bound checks and additionally enforces this listener's own frozen
// client allowlist. A live callback alone cannot broaden the Contract or
// private listener to every certificate under the configured client root.
func bindProviderClientAdmission(config *tls.Config, allowed []string) (*clientIdentityAdmission, error) {
	admission, err := newClientIdentityAdmission(allowed)
	if err != nil {
		return nil, err
	}
	previous := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := previous(state); err != nil {
			return err
		}
		return admission.VerifyConnection(state)
	}
	return admission, nil
}

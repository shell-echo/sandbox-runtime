package executorbackend

import (
	"crypto/tls"
	"errors"

	"github.com/shell-echo/sandbox-runtime/providerapi"
)

func executorServerTLS(remote *tls.Config, certificateFile, keyFile, clientCAFile string, allowed []string) (*tls.Config, error) {
	if remote == nil {
		return providerapi.LoadMTLSConfig(certificateFile, keyFile, clientCAFile, allowed)
	}
	if certificateFile != "" || keyFile != "" || clientCAFile != "" || len(allowed) != 0 ||
		remote.MinVersion != tls.VersionTLS13 || remote.MaxVersion != tls.VersionTLS13 ||
		remote.ClientAuth != tls.RequireAndVerifyClientCert || remote.ClientCAs == nil ||
		remote.GetCertificate == nil || remote.VerifyConnection == nil || len(remote.Certificates) != 0 ||
		remote.InsecureSkipVerify {
		return nil, errors.New("invalid remote executor mTLS configuration")
	}
	return remote.Clone(), nil
}

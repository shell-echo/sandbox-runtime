package phase6egress

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
)

const capacityCredentialsProtocol = "sandbox-runtime.capacity-valkey-credentials.v1"
const maxExternalCredentialBytes = 8 << 10

var externalUserPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$`)

type CapacityValkeyCredentials struct {
	Protocol string `json:"protocol"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (CapacityValkeyCredentials) String() string { return "capacity-valkey-credentials([redacted])" }
func (CapacityValkeyCredentials) GoString() string {
	return "phase6egress.CapacityValkeyCredentials{[redacted]}"
}

func (c CapacityValkeyCredentials) valid() bool {
	return c.Protocol == capacityCredentialsProtocol && c.Username != "default" &&
		externalUserPattern.MatchString(c.Username) && len(c.Password) >= 1 && len(c.Password) <= 4096 && utf8.ValidString(c.Password)
}

// DecodeCapacityValkeyCredentials accepts only the purpose-bound secret. The
// document cannot choose an endpoint, database, TLS policy or namespace.
func DecodeCapacityValkeyCredentials(document []byte) (CapacityValkeyCredentials, error) {
	if len(document) < 1 || len(document) > maxExternalCredentialBytes || !utf8.Valid(document) {
		return CapacityValkeyCredentials{}, ErrUnavailable
	}
	scan := json.NewDecoder(bytes.NewReader(document))
	opening, err := scan.Token()
	if err != nil || opening != json.Delim('{') {
		return CapacityValkeyCredentials{}, ErrUnavailable
	}
	seen := make(map[string]bool, 3)
	for scan.More() {
		name, tokenErr := scan.Token()
		key, ok := name.(string)
		if tokenErr != nil || !ok || seen[key] || key != "protocol" && key != "username" && key != "password" {
			return CapacityValkeyCredentials{}, ErrUnavailable
		}
		seen[key] = true
		value, valueErr := scan.Token()
		if valueErr != nil {
			return CapacityValkeyCredentials{}, ErrUnavailable
		}
		if _, ok := value.(string); !ok {
			return CapacityValkeyCredentials{}, ErrUnavailable
		}
	}
	closing, err := scan.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 3 {
		return CapacityValkeyCredentials{}, ErrUnavailable
	}
	if _, err := scan.Token(); !errors.Is(err, io.EOF) {
		return CapacityValkeyCredentials{}, ErrUnavailable
	}
	var credentials CapacityValkeyCredentials
	if json.Unmarshal(document, &credentials) != nil || !credentials.valid() {
		return CapacityValkeyCredentials{}, ErrUnavailable
	}
	canonical, err := json.Marshal(credentials)
	if err != nil || !bytes.Equal(canonical, document) {
		return CapacityValkeyCredentials{}, ErrUnavailable
	}
	return credentials, nil
}

type BoundPostgresTarget struct {
	Host     string
	Port     int
	Database string
	User     string
}

// WitnessTarget keeps the established action-history call surface. The strict
// parser itself is neutral so other profile-bound roles reuse the same closed
// URL and PostgreSQL environment checks without altering witness limits.
type WitnessTarget = BoundPostgresTarget

func ParseActionHistoryWitnessDSN(document []byte, target WitnessTarget) (*pgxpool.Config, error) {
	return ParseBoundPostgresDSN(document, target)
}

// ParseBoundPostgresDSN accepts one exact PostgreSQL URI target. The caller
// obtains every non-secret target field from its trusted role authority; the
// URL cannot choose TLS roots, client cert files, fallback hosts or options.
func ParseBoundPostgresDSN(document []byte, target BoundPostgresTarget) (*pgxpool.Config, error) {
	if len(document) < 1 || len(document) > maxExternalCredentialBytes || !utf8.Valid(document) ||
		!externalUserPattern.MatchString(target.User) || !externalUserPattern.MatchString(target.Database) ||
		target.Port < 1 || target.Port > 65535 || target.Host == "" || net.ParseIP(target.Host) != nil ||
		RejectPostgresEnvironment() != nil {
		return nil, ErrUnavailable
	}
	parsed, err := url.Parse(string(document))
	if err != nil || parsed == nil || parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" ||
		parsed.Opaque != "" || parsed.User == nil || parsed.RawPath != "" || parsed.Fragment != "" ||
		parsed.ForceQuery || parsed.RawQuery != "sslmode=verify-full" || parsed.Hostname() != target.Host ||
		parsed.Path != "/"+target.Database || parsed.User.Username() != target.User {
		return nil, ErrUnavailable
	}
	password, hasPassword := parsed.User.Password()
	if !hasPassword || len(password) < 1 || len(password) > 4096 || !utf8.ValidString(password) ||
		!externalUserPattern.MatchString(parsed.User.Username()) || parsed.Port() != strconv.Itoa(target.Port) {
		return nil, ErrUnavailable
	}
	canonical := (&url.URL{Scheme: parsed.Scheme, User: url.UserPassword(target.User, password),
		Host: net.JoinHostPort(target.Host, strconv.Itoa(target.Port)), Path: "/" + target.Database,
		RawQuery: "sslmode=verify-full"}).String()
	if canonical != string(document) {
		return nil, ErrUnavailable
	}
	config, err := pgxpool.ParseConfig(canonical)
	if err != nil || config.ConnConfig == nil || config.ConnConfig.Host != target.Host ||
		int(config.ConnConfig.Port) != target.Port || config.ConnConfig.Database != target.Database ||
		config.ConnConfig.User != target.User || config.ConnConfig.Password != password ||
		config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify ||
		len(config.ConnConfig.Fallbacks) != 0 {
		return nil, ErrUnavailable
	}
	return config, nil
}

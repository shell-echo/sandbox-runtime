package qualificationadapterprotocol

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
)

type invocationLocationFields struct {
	ProfilePath          string
	ProviderOrigin       string
	GatewayProbeEndpoint string
	CallerStateRoot      string
}

// ValidateSupervisorLocations applies the locked lexical location and overlap
// rules to static supervisor input. It performs no filesystem or network I/O.
// Errors deliberately omit raw locations. Existence, inode identity, directory
// privacy and pre-secret custody must be established separately.
func ValidateSupervisorLocations(profilePath, providerOrigin, gatewayEndpoint, stateRoot, workingDirectory, evidenceRoot string) error {
	invalid := errors.New("invalid supervisor locations")
	if validateInvocationLocationFields(invocationLocationFields{
		ProfilePath: profilePath, ProviderOrigin: providerOrigin,
		GatewayProbeEndpoint: gatewayEndpoint, CallerStateRoot: stateRoot,
	}) != nil {
		return invalid
	}
	if validateAbsoluteCleanPosixPath("working_directory", workingDirectory) != nil ||
		validateAbsoluteCleanPosixPath("evidence_root", evidenceRoot) != nil {
		return invalid
	}
	for _, pair := range [][2]string{
		{profilePath, workingDirectory}, {profilePath, evidenceRoot},
		{stateRoot, workingDirectory}, {stateRoot, evidenceRoot},
	} {
		if pathsOverlap(pair[0], pair[1]) {
			return invalid
		}
	}
	return nil
}

func validateInvocationLocationFields(fields invocationLocationFields) error {
	if err := validateAbsoluteCleanPosixPath("profile_path", fields.ProfilePath); err != nil {
		return err
	}
	if err := validateAbsoluteCleanPosixPath("caller_state_root", fields.CallerStateRoot); err != nil {
		return err
	}
	if pathsOverlap(fields.ProfilePath, fields.CallerStateRoot) {
		return fmt.Errorf("profile_path and caller_state_root must not overlap")
	}
	if err := validateCanonicalSecureURI("provider_origin", fields.ProviderOrigin, true); err != nil {
		return err
	}
	if err := validateCanonicalSecureURI("gateway_probe_endpoint", fields.GatewayProbeEndpoint, false); err != nil {
		return err
	}
	return nil
}

func validateReconstructionLocationBinding(initial, reconstruction invocationLocationFields) error {
	checks := []struct {
		name           string
		initial        string
		reconstruction string
	}{
		{name: "profile_path", initial: initial.ProfilePath, reconstruction: reconstruction.ProfilePath},
		{name: "provider_origin", initial: initial.ProviderOrigin, reconstruction: reconstruction.ProviderOrigin},
		{name: "gateway_probe_endpoint", initial: initial.GatewayProbeEndpoint, reconstruction: reconstruction.GatewayProbeEndpoint},
		{name: "caller_state_root", initial: initial.CallerStateRoot, reconstruction: reconstruction.CallerStateRoot},
	}
	for _, check := range checks {
		if check.initial != check.reconstruction {
			return fmt.Errorf("%s must be byte-identical across phase invocations", check.name)
		}
	}
	return nil
}

func validateAbsoluteCleanPosixPath(name, value string) error {
	if len(value) < 2 || len(value) > 1024 || !strings.HasPrefix(value, "/") || value == "/" {
		return fmt.Errorf("%s must be a bounded non-root absolute POSIX path", name)
	}
	if path.Clean(value) != value {
		return fmt.Errorf("%s must be lexically clean", name)
	}
	for _, component := range strings.Split(value[1:], "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("%s contains an invalid path component", name)
		}
		for index := 0; index < len(component); index++ {
			character := component[index]
			if !isPortablePathCharacter(character) {
				return fmt.Errorf("%s contains a non-portable path character", name)
			}
		}
	}
	return nil
}

func isPortablePathCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '.' || character == '_' || character == '-'
}

func pathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func validateCanonicalSecureURI(name, raw string, providerOrigin bool) error {
	if len(raw) == 0 || len(raw) > 2048 {
		return fmt.Errorf("%s must be a bounded URI", name)
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] < 0x21 || raw[index] > 0x7e {
			return fmt.Errorf("%s must contain printable ASCII only", name)
		}
	}
	if strings.ContainsAny(raw, "\\%?#@") {
		return fmt.Errorf("%s must not contain userinfo, percent encoding, query, fragment, or backslash material", name)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URI: %w", name, err)
	}
	if !parsed.IsAbs() || parsed.Opaque != "" || parsed.OmitHost || parsed.User != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("%s must be an absolute hierarchical URI with one authority", name)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return fmt.Errorf("%s must not contain a query or fragment", name)
	}
	if parsed.RawPath != "" || parsed.String() != raw {
		return fmt.Errorf("%s must use one canonical raw spelling", name)
	}

	if providerOrigin {
		if parsed.Scheme != "https" || parsed.Path != "" {
			return fmt.Errorf("provider_origin must be an https origin without a path")
		}
	} else {
		if parsed.Scheme != "https" && parsed.Scheme != "wss" {
			return fmt.Errorf("gateway_probe_endpoint must use https or wss")
		}
		if err := validateGatewayPath(parsed.Path); err != nil {
			return err
		}
	}
	if err := validateCanonicalAuthority(name, parsed); err != nil {
		return err
	}
	return nil
}

func validateCanonicalAuthority(name string, parsed *url.URL) error {
	host, port, bracketed, err := splitCanonicalAuthority(parsed.Host)
	if err != nil {
		return fmt.Errorf("%s authority is invalid: %w", name, err)
	}
	if err := validateCanonicalHost(host, bracketed); err != nil {
		return fmt.Errorf("%s host is invalid: %w", name, err)
	}
	if port == "" {
		return nil
	}
	for index := 0; index < len(port); index++ {
		if port[index] < '0' || port[index] > '9' {
			return fmt.Errorf("%s port must contain decimal digits only", name)
		}
	}
	if len(port) > 1 && port[0] == '0' {
		return fmt.Errorf("%s port must use shortest decimal form", name)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("%s port must be in the range 1..65535", name)
	}
	if number == 443 {
		return fmt.Errorf("%s must omit the default port 443", name)
	}
	return nil
}

func splitCanonicalAuthority(authority string) (host, port string, bracketed bool, err error) {
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing < 0 {
			return "", "", false, fmt.Errorf("missing IPv6 closing bracket")
		}
		host = authority[1:closing]
		bracketed = true
		remainder := authority[closing+1:]
		if remainder == "" {
			return host, "", bracketed, nil
		}
		if !strings.HasPrefix(remainder, ":") || len(remainder) == 1 {
			return "", "", false, fmt.Errorf("invalid bracketed-host port")
		}
		return host, remainder[1:], bracketed, nil
	}
	if strings.Count(authority, ":") > 1 {
		return "", "", false, fmt.Errorf("IPv6 literals must be bracketed")
	}
	host, port, found := strings.Cut(authority, ":")
	if !found {
		return authority, "", false, nil
	}
	if host == "" || port == "" {
		return "", "", false, fmt.Errorf("empty host or port")
	}
	return host, port, false, nil
}

func validateCanonicalHost(host string, bracketed bool) error {
	if host == "" || strings.ContainsAny(host, "%\\") {
		return fmt.Errorf("empty, zoned, or escaped host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			if bracketed || host != ip.String() {
				return fmt.Errorf("IPv4 address is not canonical")
			}
			return nil
		}
		if !bracketed || host != ip.String() {
			return fmt.Errorf("IPv6 address is not canonical RFC 5952 form")
		}
		return nil
	}
	if bracketed || len(host) > 253 || host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return fmt.Errorf("DNS name is not canonical lowercase LDH form")
	}
	hasLetter := false
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("DNS label is invalid")
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if character >= 'a' && character <= 'z' {
				hasLetter = true
				continue
			}
			if character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return fmt.Errorf("DNS label contains a non-LDH character")
		}
	}
	if !hasLetter {
		return fmt.Errorf("numeric host must use canonical IPv4 form")
	}
	if hostEndsInAmbiguousIPv4Number(host) {
		return fmt.Errorf("DNS name must not end in a WHATWG IPv4 number")
	}
	return nil
}

func hostEndsInAmbiguousIPv4Number(host string) bool {
	last := host
	if index := strings.LastIndexByte(host, '.'); index >= 0 {
		last = host[index+1:]
	}
	if last == "" {
		return false
	}
	allDecimal := true
	for index := 0; index < len(last); index++ {
		if last[index] < '0' || last[index] > '9' {
			allDecimal = false
			break
		}
	}
	if allDecimal {
		return true
	}
	if !strings.HasPrefix(last, "0x") {
		return false
	}
	for index := 2; index < len(last); index++ {
		character := last[index]
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validateGatewayPath(value string) error {
	if value == "" || !strings.HasPrefix(value, "/") {
		return fmt.Errorf("gateway_probe_endpoint must contain an absolute path")
	}
	if value == "/" {
		return nil
	}
	if path.Clean(value) != value || strings.HasSuffix(value, "/") {
		return fmt.Errorf("gateway_probe_endpoint path must be lexically clean")
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("gateway_probe_endpoint contains an invalid path segment")
		}
		for index := 0; index < len(segment); index++ {
			character := segment[index]
			if !isGatewayPathCharacter(character) {
				return fmt.Errorf("gateway_probe_endpoint contains a non-portable path character")
			}
		}
	}
	return nil
}

func isGatewayPathCharacter(character byte) bool {
	return isPortablePathCharacter(character) || character == '~' || character == ':'
}

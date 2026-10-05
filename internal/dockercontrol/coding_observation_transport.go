package dockercontrol

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const MaxCodingObservationResponseBytes = 1 << 20
const maxCodingArchiveResponseBytes = 32 << 10

var ErrInvalidCodingObservationTransport = errors.New("invalid private Coding read-only Docker transport")
var codingArchiveRuntimeID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// codingObservationTransport is installed as the frozen client's actual
// RoundTripper, before the Moby SDK reads a response. It is not a response
// hook: that SDK explicitly forbids response hooks from reading or closing
// Body. The transport rejects all unreviewed requests *before* forwarding
// them and returns a non-NotFound error for oversized/truncated 404 bodies.
type codingObservationTransport struct {
	base         http.RoundTripper
	set          CodingResourceSet
	endpointHost string
	requestHost  string
	imageRef     string
	platform     string
	archiveID    string // set only after exact runtime ownership/config verification
	archiveUID   int
	archiveGID   int
	archiveMode  int64
}

func (t *codingObservationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil || request == nil || request.Context().Err() != nil ||
		!t.allowed(request) {
		return nil, ErrInvalidCodingObservationTransport
	}
	response, err := t.base.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrInvalidCodingObservationTransport
	}
	maximum := MaxCodingObservationResponseBytes
	if t.isArchiveRequest(request) {
		maximum = maxCodingArchiveResponseBytes
	}
	if response.ContentLength > int64(maximum) {
		_ = response.Body.Close()
		return nil, ErrInvalidCodingObservationTransport
	}
	document, readErr := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || request.Context().Err() != nil ||
		len(document) > maximum ||
		(response.ContentLength >= 0 && int64(len(document)) != response.ContentLength) ||
		!t.validResponse(request, response, document) {
		return nil, ErrInvalidCodingObservationTransport
	}
	response.Body = io.NopCloser(bytes.NewReader(document))
	response.ContentLength = int64(len(document))
	if response.Header != nil {
		response.Header.Set("Content-Length", strconv.Itoa(len(document)))
	}
	return response, nil
}

func (t *codingObservationTransport) validResponse(request *http.Request, response *http.Response, document []byte) bool {
	if t.isArchiveRequest(request) {
		return response.StatusCode == http.StatusOK && t.validArchiveResponse(request, response, document)
	}
	if response.StatusCode == http.StatusNotFound {
		return t.isInspectPath(request.URL.Path) && validCodingNotFound(response.Header, document)
	}
	if response.StatusCode != http.StatusOK || !json.Valid(document) {
		return false
	}
	trimmed := bytes.TrimSpace(document)
	switch request.URL.Path {
	case "/v1.55/containers/json":
		var items []json.RawMessage
		return len(trimmed) > 0 && trimmed[0] == '[' && json.Unmarshal(trimmed, &items) == nil
	case "/v1.55/volumes":
		return validCodingVolumeList(trimmed)
	default:
		return true
	}
}

func (t *codingObservationTransport) isArchiveRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || !codingArchiveRuntimeID.MatchString(t.archiveID) ||
		request.URL.Path != "/v1.55/containers/"+t.archiveID+"/archive" {
		return false
	}
	for _, mount := range t.set.Mounts() {
		if request.URL.RawQuery == (url.Values{"path": {mount.Target}}).Encode() {
			return true
		}
	}
	return false
}

func (t *codingObservationTransport) validArchiveResponse(request *http.Request,
	response *http.Response, document []byte) bool {
	media, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/x-tar" || len(params) != 0 ||
		len(document) < 3*512 || len(document)%512 != 0 || document[156] != tar.TypeDir {
		return false
	}
	var target string
	for _, mount := range t.set.Mounts() {
		if request.URL.RawQuery == (url.Values{"path": {mount.Target}}).Encode() {
			target = mount.Target
		}
	}
	if target == "" || t.archiveUID <= 0 || t.archiveGID <= 0 || t.archiveMode != 0o770 {
		return false
	}
	name := strings.TrimPrefix(target, "/")
	statValues := response.Header.Values("X-Docker-Container-Path-Stat")
	if len(statValues) != 1 {
		return false
	}
	statEncoded := statValues[0]
	if len(statEncoded) == 0 || len(statEncoded) > 4096 {
		return false
	}
	statDocument, err := base64.StdEncoding.DecodeString(statEncoded)
	if err != nil || len(statDocument) > 2048 {
		return false
	}
	fields, ok := codingJSONObjectFields(statDocument)
	if !ok || len(fields) == 0 {
		return false
	}
	for _, required := range []string{"name", "size", "mode", "linkTarget"} {
		if _, present := fields[required]; !present {
			return false
		}
	}
	for field := range fields {
		if field != "name" && field != "size" && field != "mode" &&
			field != "mtime" && field != "linkTarget" {
			return false
		}
	}
	var stat container.PathStat
	uid, gid, mode := t.archiveUID, t.archiveGID, t.archiveMode
	if target == "/inputs" {
		uid, gid, mode = 0, 0, 0o555
	}
	if json.Unmarshal(statDocument, &stat) != nil || stat.Name != name ||
		stat.Mode != os.ModeDir|os.FileMode(mode) || stat.LinkTarget != "" ||
		stat.Size < 0 || stat.Size > maxCodingArchiveResponseBytes {
		return false
	}
	reader := tar.NewReader(bytes.NewReader(document))
	header, err := reader.Next()
	if err != nil || header.Typeflag != tar.TypeDir ||
		(header.Name != name && header.Name != name+"/") ||
		header.Uid != uid || header.Gid != gid || header.Mode != mode ||
		header.Size != 0 || header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
		return false
	}
	if _, err := reader.Next(); err != io.EOF {
		return false
	}
	for _, value := range document[512:] {
		if value != 0 {
			return false
		}
	}
	return true
}

func (t *codingObservationTransport) isInspectPath(path string) bool {
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		name, err := t.set.ContainerName(role)
		if err == nil && path == "/v1.55/containers/"+name+"/json" {
			return true
		}
	}
	for _, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, err := t.set.VolumeName(role)
		if err == nil && path == "/v1.55/volumes/"+name {
			return true
		}
	}
	return false
}

// A malformed 404 is not evidence that an inspected object is absent. The
// fixed daemon API's error body is a JSON object with one nonempty message.
func validCodingNotFound(header http.Header, document []byte) bool {
	media, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		(len(params) > 0 && (len(params) != 1 || !strings.EqualFold(params["charset"], "utf-8"))) {
		return false
	}
	fields, ok := codingJSONObjectFields(document)
	if !ok || len(fields) != 1 {
		return false
	}
	var message string
	return json.Unmarshal(fields["message"], &message) == nil && strings.TrimSpace(message) != "" && len(message) <= 4096
}

func validCodingVolumeList(document []byte) bool {
	fields, ok := codingJSONObjectFields(document)
	if !ok {
		return false
	}
	// encoding/json matches struct members case-insensitively. A later alias
	// could overwrite a required field or conceal a warning after this check.
	for name := range fields {
		if (strings.EqualFold(name, "Volumes") && name != "Volumes") ||
			(strings.EqualFold(name, "Warnings") && name != "Warnings") {
			return false
		}
	}
	volumes, present := fields["Volumes"]
	volumes = bytes.TrimSpace(volumes)
	if !present || len(volumes) == 0 || volumes[0] != '[' {
		return false
	}
	var items []json.RawMessage
	if json.Unmarshal(volumes, &items) != nil {
		return false
	}
	if warnings, present := fields["Warnings"]; present {
		warnings = bytes.TrimSpace(warnings)
		if string(warnings) == "null" {
			return true
		}
		var messages []string
		if len(warnings) == 0 || warnings[0] != '[' || json.Unmarshal(warnings, &messages) != nil {
			return false
		}
	}
	return true
}

// Decode top-level members once so duplicate keys cannot silently replace
// the required Docker response fields. Unrelated future fields stay opaque.
func codingJSONObjectFields(document []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		fields[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, false
	}
	_, err = decoder.Token()
	return fields, err == io.EOF
}

func (t *codingObservationTransport) allowed(request *http.Request) bool {
	if request.Method != http.MethodGet || request.URL == nil || request.URL.Scheme != "http" ||
		request.URL.Host != t.endpointHost || t.endpointHost == "" ||
		request.Host != t.requestHost || t.requestHost == "" ||
		request.URL.User != nil || request.URL.Opaque != "" || request.URL.ForceQuery ||
		request.URL.RawPath != "" ||
		request.URL.EscapedPath() != request.URL.Path ||
		!strings.HasPrefix(request.URL.Path, "/v1.55/") ||
		request.URL.Fragment != "" {
		return false
	}
	path := strings.TrimPrefix(request.URL.Path, "/v1.55")
	if path == "/info" {
		return request.URL.RawQuery == ""
	}
	if t.imageRef != "" && path == "/images/"+t.imageRef+"/json" {
		platformQuery, ok := codingImageInspectPlatformQuery(t.platform)
		return ok && (request.URL.RawQuery == "" || request.URL.RawQuery == platformQuery)
	}
	if t.isArchiveRequest(request) {
		return true
	}
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		name, err := t.set.ContainerName(role)
		if err == nil && path == "/containers/"+name+"/json" && request.URL.RawQuery == "" {
			return true
		}
	}
	for _, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, err := t.set.VolumeName(role)
		if err == nil && path == "/volumes/"+name && request.URL.RawQuery == "" {
			return true
		}
	}
	filters := make(client.Filters).Add("label", codingEffectLabel+"="+t.set.effectID)
	encoded, err := json.Marshal(filters)
	if err != nil {
		return false
	}
	if path == "/containers/json" {
		return request.URL.RawQuery == (url.Values{"all": {"1"}, "filters": {string(encoded)}}).Encode()
	}
	if path == "/volumes" {
		return request.URL.RawQuery == (url.Values{"filters": {string(encoded)}}).Encode()
	}
	return false
}

func codingImageInspectPlatformQuery(platform string) (string, bool) {
	selected, ok := codingOCIPlatform(platform)
	if !ok {
		return "", false
	}
	document, err := json.Marshal(selected)
	if err != nil {
		return "", false
	}
	return (url.Values{"platform": {string(document)}}).Encode(), true
}

func codingOCIPlatform(platform string) (ocispec.Platform, bool) {
	selected := ocispec.Platform{OS: "linux"}
	switch platform {
	case "linux/arm64/v8":
		selected.Architecture, selected.Variant = "arm64", "v8"
	case "linux/amd64":
		selected.Architecture = "amd64"
	default:
		return ocispec.Platform{}, false
	}
	return selected, true
}

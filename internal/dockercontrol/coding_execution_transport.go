package dockercontrol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/moby/moby/client"
)

// The new mode has its own allowlist. No mutation, exec, log, archive-upload,
// arbitrary path, unfiltered list, or legacy three-volume resource set enters.
type executionObservationTransport struct {
	base         http.RoundTripper
	endpointHost string
	binding      executionBinding
	create       executionCreate
	archiveID    string      // enabled only after exact initial resident/image checks
	checkSocket  func() bool // production constructor pins dev/inode and socket policy
}

func (t *executionObservationTransport) archiveIndex(r *http.Request) int {
	if r == nil || r.URL == nil || !codingArchiveRuntimeID.MatchString(t.archiveID) || r.URL.Path != "/v1.55/containers/"+t.archiveID+"/archive" {
		return -1
	}
	for i, target := range executionTargets {
		if r.URL.RawQuery == (url.Values{"path": {target}}).Encode() {
			return i
		}
	}
	return -1
}
func (t *executionObservationTransport) inspectPath(path string) bool {
	r := t.create.resources(t.binding)
	if path == "/v1.55/containers/"+r.Preparation+"/json" || path == "/v1.55/containers/"+r.Resident+"/json" {
		return true
	}
	for _, name := range r.Volumes {
		if path == "/v1.55/volumes/"+name {
			return true
		}
	}
	return false
}
func (t *executionObservationTransport) allowed(r *http.Request) bool {
	if r == nil || r.URL == nil || r.Method != "GET" || r.URL.Scheme != "http" || r.URL.Host != t.endpointHost || t.endpointHost == "" ||
		r.Host != client.DummyHost || r.URL.User != nil || r.URL.Opaque != "" || r.URL.ForceQuery || r.URL.RawPath != "" ||
		r.URL.EscapedPath() != r.URL.Path || r.URL.Fragment != "" || r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) {
		return false
	}
	if r.URL.Path == "/v1.55/info" || t.inspectPath(r.URL.Path) {
		return r.URL.RawQuery == ""
	}
	if r.URL.Path == "/v1.55/images/"+t.binding.Template.Image.Reference+"/json" {
		platform, ok := codingImageInspectPlatformQuery(t.binding.Template.Image.Platform)
		return ok && (r.URL.RawQuery == "" || r.URL.RawQuery == platform)
	}
	if t.archiveIndex(r) >= 0 {
		return true
	}
	filters, _ := json.Marshal(make(client.Filters).Add("label", executionScopeLabel+"="+t.create.digest()))
	if r.URL.Path == "/v1.55/containers/json" {
		return r.URL.RawQuery == (url.Values{"all": {"1"}, "filters": {string(filters)}}).Encode()
	}
	if r.URL.Path == "/v1.55/volumes" {
		return r.URL.RawQuery == (url.Values{"filters": {string(filters)}}).Encode()
	}
	return false
}
func (t *executionObservationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil || !t.allowed(r) || r.Context().Err() != nil || (t.checkSocket != nil && !t.checkSocket()) {
		return nil, ErrInvalidCodingObservationTransport
	}
	response, err := t.base.RoundTrip(r)
	if err != nil || response == nil || response.Body == nil || response.Header == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrInvalidCodingObservationTransport
	}
	maximum := MaxCodingObservationResponseBytes
	archive := t.archiveIndex(r)
	if archive >= 0 {
		maximum = maxCodingArchiveResponseBytes
	}
	if response.ContentLength > int64(maximum) {
		_ = response.Body.Close()
		return nil, ErrInvalidCodingObservationTransport
	}
	d, readErr := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(d) > maximum || r.Context().Err() != nil || (t.checkSocket != nil && !t.checkSocket()) || (response.ContentLength >= 0 && response.ContentLength != int64(len(d))) {
		return nil, ErrInvalidCodingObservationTransport
	}
	valid := false
	if archive >= 0 {
		uid, gid, mode := executionRootOwner(t.create.resources(t.binding), archive)
		valid = response.StatusCode == 200 && validCodingEmptyRootArchive(executionTargets[archive], uid, gid, mode, response, d)
	} else if response.StatusCode == 404 {
		valid = t.inspectPath(r.URL.Path) && validCodingNotFound(response.Header, d)
	} else if response.StatusCode == 200 && json.Valid(d) && executionJSONUnambiguous(d) {
		switch r.URL.Path {
		case "/v1.55/volumes":
			valid = validCodingVolumeList(d)
		case "/v1.55/containers/json":
			var items []json.RawMessage
			trimmed := bytes.TrimSpace(d)
			valid = len(trimmed) > 0 && trimmed[0] == '[' && json.Unmarshal(d, &items) == nil
		default:
			_, valid = codingJSONObjectFields(d)
		}
	}
	if !valid {
		return nil, ErrInvalidCodingObservationTransport
	}
	response.Body = io.NopCloser(bytes.NewReader(d))
	response.ContentLength = int64(len(d))
	response.Header.Set("Content-Length", strconv.Itoa(len(d)))
	return response, nil
}

// Moby decoding is case insensitive. Reject duplicate/alias members at every
// level before it can overwrite a checked value; limit nesting work as well.
func executionJSONUnambiguous(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	var read func(int) bool
	read = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return false
				}
				name = strings.ToLower(name)
				if seen[name] {
					return false
				}
				seen[name] = true
				if !read(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		}
		if delim == '[' {
			for d.More() {
				if !read(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		}
		return false
	}
	if !read(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

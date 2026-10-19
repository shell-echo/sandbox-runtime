package dockercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/moby/moby/api/types/volume"
)

var ErrInvalidCodingCreation = errors.New("invalid private Coding creation")

// This is a finite, single-use write capability, separate from the observer's
// GET-only SDK. No exported method accepts a URL, Docker options, or a body.
// Each step is consumed before sending, even on an uncertain response. Fresh
// connections and direct RoundTrip prevent retries and redirects.
type codingUnixCreation struct {
	plan              codingCreationPlan
	platform          string
	base              *http.Transport
	wire              http.RoundTripper
	step              int
	failed            bool
	prepID, runtimeID string
}

func newCodingUnixCreation(endpoint codingBoundUnixEndpoint, plan codingCreationPlan, platform string) (*codingUnixCreation, error) {
	if verifyCodingUnixSocket(endpoint.path) != nil || !controlDigest.MatchString(endpoint.scopeDigest) {
		return nil, ErrInvalidCodingCreation
	}
	base := newCodingObservationHTTPTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if verifyCodingUnixSocket(endpoint.path) != nil {
			return nil, ErrInvalidCodingCreation
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", endpoint.path)
	})
	base.DisableKeepAlives = true
	return &codingUnixCreation{plan: plan, platform: platform, base: base, wire: base}, nil
}

func (w *codingUnixCreation) close() {
	if w != nil && w.base != nil {
		w.base.CloseIdleConnections()
	}
}

// request derives the complete wire document from the already verified plan.
// There is no mutation hook between this derivation and the fixed Unix dial.
func (w *codingUnixCreation) request(ctx context.Context) (*http.Request, int, error) {
	method, path, contentType, status := "POST", "", "application/json", http.StatusCreated
	var body []byte
	query := url.Values{}
	switch w.step {
	case 0, 1, 2:
		path, body = "/volumes/create", w.plan.volumeBodies[w.step]
	case 3, 6:
		path = "/containers/create"
		name := w.plan.prepName
		body = w.plan.prepBody
		if w.step == 6 {
			name, body = w.plan.runtimeName, w.plan.runtimeBody
		}
		query.Set("name", name)
		query.Set("platform", w.platform)
	case 4:
		if !codingArchiveRuntimeID.MatchString(w.prepID) {
			return nil, 0, ErrInvalidCodingCreation
		}
		method, path, body, contentType, status = "PUT", "/containers/"+w.prepID+"/archive", w.plan.archive, "application/x-tar", http.StatusOK
		query.Set("path", "/")
		query.Set("noOverwriteDirNonDir", "true")
	case 5:
		if !codingArchiveRuntimeID.MatchString(w.prepID) {
			return nil, 0, ErrInvalidCodingCreation
		}
		method, path, contentType, status = "DELETE", "/containers/"+w.prepID, "", http.StatusNoContent
	case 7:
		if !codingArchiveRuntimeID.MatchString(w.runtimeID) {
			return nil, 0, ErrInvalidCodingCreation
		}
		path, contentType, status = "/containers/"+w.runtimeID+"/start", "", http.StatusNoContent
	default:
		return nil, 0, ErrInvalidCodingCreation
	}
	if len(body) > MaxCodingObservationResponseBytes {
		return nil, 0, ErrInvalidCodingCreation
	}
	u := &url.URL{Scheme: "http", Host: "docker", Path: "/v1.55" + path, RawQuery: query.Encode()}
	request, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, ErrInvalidCodingCreation
	}
	request.GetBody = nil
	request.Close = true
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	return request, status, nil
}

func (w *codingUnixCreation) next(ctx context.Context) error {
	if w == nil || w.wire == nil || w.failed || ctx == nil || ctx.Err() != nil {
		return ErrInvalidCodingCreation
	}
	bounded, cancel := context.WithTimeout(ctx, maxCodingObservationRequestDuration)
	defer cancel()
	request, status, err := w.request(bounded)
	if err != nil {
		w.failed = true
		return ErrInvalidCodingCreation
	}
	step := w.step
	w.step++
	w.failed = true // never clear after an ambiguous send, body, or response
	response, err := w.wire.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ErrInvalidCodingCreation
	}
	defer response.Body.Close()
	if response.StatusCode != status || response.ContentLength > MaxCodingObservationResponseBytes ||
		response.Header.Get("Content-Encoding") != "" ||
		(len(response.TransferEncoding) != 0 && (len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked")) {
		return ErrInvalidCodingCreation
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, MaxCodingObservationResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || bounded.Err() != nil || (response.ContentLength >= 0 && int64(len(body)) != response.ContentLength) ||
		len(body) > MaxCodingObservationResponseBytes {
		return ErrInvalidCodingCreation
	}
	if step == 4 || step == 5 || step == 7 {
		if len(body) != 0 || response.ContentLength != 0 || len(response.TransferEncoding) != 0 {
			return ErrInvalidCodingCreation
		}
	} else {
		media, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || (len(params) != 0 && (len(params) != 1 || !strings.EqualFold(params["charset"], "utf-8"))) {
			return ErrInvalidCodingCreation
		}
		fields, ok := codingJSONObjectFields(body)
		if !ok {
			return ErrInvalidCodingCreation
		}
		if step < 3 {
			if !validCodingCreatedVolumeFields(fields) {
				return ErrInvalidCodingCreation
			}
			var observed volume.Volume
			role := []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole}[step]
			name, _ := w.plan.set.VolumeName(role)
			if json.Unmarshal(body, &observed) != nil || observed.Name != name || observed.Driver != "local" || observed.Scope != "local" ||
				len(observed.Options) != 0 || w.plan.set.MatchLabels(role, observed.Labels) != nil {
				return ErrInvalidCodingCreation
			}
		} else {
			var observed struct {
				ID       string `json:"Id"`
				Warnings []string
			}
			if len(fields) != 2 || fields["Id"] == nil || fields["Warnings"] == nil || json.Unmarshal(body, &observed) != nil ||
				!codingArchiveRuntimeID.MatchString(observed.ID) || len(observed.Warnings) != 0 {
				return ErrInvalidCodingCreation
			}
			if step == 3 {
				w.prepID = observed.ID
			} else {
				if observed.ID == w.prepID {
					return ErrInvalidCodingCreation
				}
				w.runtimeID = observed.ID
			}
		}
	}
	w.failed = false
	return nil
}

// The SDK struct decoder is case-insensitive and silently collapses duplicate
// map keys. Validate the exact v1.55 local-volume response grammar first, so
// conflicting Name/name or duplicate Labels cannot become an apparent success.
func validCodingCreatedVolumeFields(fields map[string]json.RawMessage) bool {
	for _, required := range []string{"Driver", "Labels", "Mountpoint", "Name", "Options", "Scope"} {
		if fields[required] == nil {
			return false
		}
	}
	for key, value := range fields {
		switch key {
		case "Driver", "Mountpoint", "Name", "Scope", "CreatedAt":
			trimmed := bytes.TrimSpace(value)
			var text string
			if len(trimmed) == 0 || trimmed[0] != '"' || json.Unmarshal(value, &text) != nil {
				return false
			}
		case "Labels":
			labels, ok := codingJSONObjectFields(value)
			if !ok || len(labels) == 0 {
				return false
			}
			for _, item := range labels {
				trimmed := bytes.TrimSpace(item)
				var text string
				if len(trimmed) == 0 || trimmed[0] != '"' || json.Unmarshal(item, &text) != nil {
					return false
				}
			}
		case "Options":
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				continue
			}
			options, ok := codingJSONObjectFields(value)
			if !ok || len(options) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

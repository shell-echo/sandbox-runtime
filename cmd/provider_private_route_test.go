package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProviderV3PrivateTerminalRouteIsExact(t *testing.T) {
	handler := exactProviderPrivateTerminalRoute(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
	}), "/private/terminal")
	for _, candidate := range []struct {
		path string
		want int
	}{
		{"/private/terminal", http.StatusAccepted},
		{"/private/terminal?alternate=true", http.StatusNotFound},
		{"/private/terminal/", http.StatusNotFound},
		{"/v1/capabilities", http.StatusNotFound},
		{"/private/%74erminal", http.StatusNotFound},
	} {
		request := httptest.NewRequest(http.MethodGet, candidate.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != candidate.want {
			t.Fatalf("route %q: status=%d, want %d", candidate.path, response.Code, candidate.want)
		}
	}
}

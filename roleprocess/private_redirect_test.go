package roleprocess

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPrivateClientRejectsRedirectBeforeSecondRequest(t *testing.T) {
	var hits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, second.URL, http.StatusFound)
	}))
	defer first.Close()
	client := &http.Client{CheckRedirect: rejectPrivateRedirect}
	response, err := client.Get(first.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || hits.Load() != 0 {
		t.Fatalf("private redirect status=%d second-endpoint hits=%d", response.StatusCode, hits.Load())
	}
}

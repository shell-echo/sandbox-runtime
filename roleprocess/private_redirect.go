package roleprocess

import "net/http"

// A private WebSocket's profile fixes its origin and route. Redirects cannot
// extend that edge, even when the TLS transport would reject a new address.
func rejectPrivateRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

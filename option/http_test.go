package option

import "testing"

// TestHTTPValidate covers the listener validation rules: port range and host
// whitespace. An empty host is valid (binds all interfaces).
func TestHTTPValidate(t *testing.T) {
	tests := []struct {
		name    string
		h       HTTP
		wantErr bool
	}{
		{"valid", HTTP{Host: "0.0.0.0", Port: 8080}, false},
		{"empty host ok", HTTP{Port: 80}, false},
		{"port zero", HTTP{Port: 0}, true},
		{"negative port", HTTP{Port: -1}, true},
		{"port too high", HTTP{Port: 70000}, true},
		{"host whitespace", HTTP{Host: "0.0.0.0 ", Port: 80}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.h
			if err := h.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestHTTPAddr checks host:port joining, including the empty-host case.
func TestHTTPAddr(t *testing.T) {
	if got := (&HTTP{Host: "127.0.0.1", Port: 9090}).Addr(); got != "127.0.0.1:9090" {
		t.Errorf("Addr() = %q, want 127.0.0.1:9090", got)
	}
	if got := (&HTTP{Port: 8080}).Addr(); got != ":8080" {
		t.Errorf("Addr() = %q, want :8080", got)
	}
}

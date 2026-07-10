package logger

import "testing"

// TestFileValidate covers the file-config rules: an empty name disables file
// logging (ok); parent-directory escapes are rejected by path segment (not by
// substring, so dots inside a filename are allowed); and the numeric bounds are
// enforced. It also confirms the name is normalised in place on success.
func TestFileValidate(t *testing.T) {
	tests := []struct {
		name    string
		file    File
		wantErr bool
	}{
		{"empty name ok", File{}, false},
		{"valid", File{Name: "/var/log/app.log", MaxSize: 10}, false},
		{"dotdot segment rejected", File{Name: "../etc/passwd", MaxSize: 10}, true},
		{"dotdot nested rejected", File{Name: "logs/../../etc", MaxSize: 10}, true},
		{"dots in filename allowed", File{Name: "/var/log/app..2.log", MaxSize: 10}, false},
		{"zero max size rejected", File{Name: "/var/log/app.log", MaxSize: 0}, true},
		{"negative backups rejected", File{Name: "/var/log/app.log", MaxSize: 10, MaxBackups: -1}, true},
		{"negative max age rejected", File{Name: "/var/log/app.log", MaxSize: 10, MaxAge: -1}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.file
			err := f.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}

	// On success, a non-empty name is cleaned in place.
	f := File{Name: "logs/./app.log", MaxSize: 10}
	if err := f.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Name != "logs/app.log" {
		t.Errorf("Name not normalised: got %q, want logs/app.log", f.Name)
	}
}

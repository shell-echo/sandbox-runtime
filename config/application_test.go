package config

import "testing"

// TestApplicationModeString confirms the ApplicationMode stringer returns the
// underlying string for both known modes.
func TestApplicationModeString(t *testing.T) {
	if ApplicationDevelopmentMode.String() != "development" {
		t.Errorf("got %q", ApplicationDevelopmentMode.String())
	}
	if ApplicationProductionMode.String() != "production" {
		t.Errorf("got %q", ApplicationProductionMode.String())
	}
}

// TestTimeZoneLocation covers all three Location branches: a named IANA zone, a
// fixed zone when the name is empty, and an error for an unresolvable name.
func TestTimeZoneLocation(t *testing.T) {
	loc, err := ApplicationTimeZone{Name: "America/New_York"}.Location()
	if err != nil {
		t.Fatalf("named zone: %v", err)
	}
	if loc.String() != "America/New_York" {
		t.Errorf("loc = %v", loc)
	}

	loc, err = ApplicationTimeZone{FixedZone: ApplicationFixedZone{Name: "CST", Offset: 8 * 3600}}.Location()
	if err != nil {
		t.Fatalf("fixed zone: %v", err)
	}
	if loc.String() != "CST" {
		t.Errorf("fixed loc = %v", loc)
	}

	if _, err := (ApplicationTimeZone{Name: "Not/AZone"}).Location(); err == nil {
		t.Error("expected error for invalid zone name")
	}
}

// TestApplicationValidate checks the validation rules: a name is required and
// the mode must be one of the two known values.
func TestApplicationValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ApplicationConfig
		wantErr bool
	}{
		{"valid", ApplicationConfig{Name: "a", Mode: ApplicationProductionMode}, false},
		{"empty name", ApplicationConfig{Mode: ApplicationProductionMode}, true},
		{"bad mode", ApplicationConfig{Name: "a", Mode: "weird"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if err := cfg.validate(); (err != nil) != tc.wantErr {
				t.Errorf("validate() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestIsDevelopment confirms IsDevelopment reflects the configured mode.
func TestIsDevelopment(t *testing.T) {
	if !(&ApplicationConfig{Mode: ApplicationDevelopmentMode}).IsDevelopment() {
		t.Error("development mode should report IsDevelopment true")
	}
	if (&ApplicationConfig{Mode: ApplicationProductionMode}).IsDevelopment() {
		t.Error("production mode should report IsDevelopment false")
	}
}

// TestDefaultApplicationConfig confirms the built-in defaults are internally
// consistent and pass validation.
func TestDefaultApplicationConfig(t *testing.T) {
	app := defaultApplicationConfig()
	if app.Name == "" || app.Mode != ApplicationProductionMode || app.TimeLocation == nil {
		t.Errorf("unexpected default application config: %+v", app)
	}
	if err := app.validate(); err != nil {
		t.Errorf("default application config should be valid: %v", err)
	}
}

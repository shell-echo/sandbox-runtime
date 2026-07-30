package config

import (
	"errors"
	"fmt"
	"time"
	_ "time/tzdata" // embed the timezone database so LoadLocation works without host tzdata

	"github.com/spf13/viper"
)

// Defaults for the application section, used when the config omits values.
const (
	defaultApplicationName            = "sandbox-runtime"
	defaultApplicationTimeZoneName    = "Asia/Shanghai"
	defaultApplicationFixedZoneName   = "CST"
	defaultApplicationFixedZoneOffset = 8 * 60 * 60
)

// ApplicationMode is the run mode of the application.
type ApplicationMode string

// String returns the mode as a plain string.
func (m ApplicationMode) String() string { return string(m) }

// The supported application modes.
const (
	ApplicationDevelopmentMode ApplicationMode = "development"
	ApplicationProductionMode  ApplicationMode = "production"
)

// ApplicationTimeZone configures the process time zone. Name is an IANA zone
// (e.g. "Asia/Shanghai"); when empty, FixedZone is used instead.
type ApplicationTimeZone struct {
	Name      string               `mapstructure:"name"`
	FixedZone ApplicationFixedZone `mapstructure:"fixed_zone"`
}

// ApplicationFixedZone is a fixed-offset fallback time zone, used when no IANA
// name is given. Offset is in seconds east of UTC.
type ApplicationFixedZone struct {
	Name   string `mapstructure:"name"`
	Offset int    `mapstructure:"offset"`
}

// Location resolves the configured zone to a *time.Location. With an empty Name
// it returns the fixed-offset zone; otherwise it loads the named IANA zone and
// errors if the name is unknown.
func (tz ApplicationTimeZone) Location() (*time.Location, error) {
	if tz.Name == "" {
		return time.FixedZone(tz.FixedZone.Name, tz.FixedZone.Offset), nil
	}
	loc, err := time.LoadLocation(tz.Name)
	if err != nil {
		return nil, fmt.Errorf("application.timezone.name %q invalid: %w", tz.Name, err)
	}
	return loc, nil
}

// ApplicationConfig is the parsed application section. TimeLocation is derived
// from TimeZone during load and is not itself read from config.
type ApplicationConfig struct {
	Name         string              `mapstructure:"name"`
	Mode         ApplicationMode     `mapstructure:"mode"`
	TimeZone     ApplicationTimeZone `mapstructure:"timezone"`
	TimeLocation *time.Location      `mapstructure:"-"`
}

// IsDevelopment reports whether the application is in development mode.
func (c *ApplicationConfig) IsDevelopment() bool { return c.Mode == ApplicationDevelopmentMode }

// validate enforces that a name is set and the mode is one of the known values.
func (c *ApplicationConfig) validate() error {
	if c.Name == "" {
		return errors.New("application.name is required")
	}
	switch c.Mode {
	case ApplicationDevelopmentMode, ApplicationProductionMode:
	default:
		return fmt.Errorf("application.mode %q invalid (%s|%s)", c.Mode, ApplicationDevelopmentMode, ApplicationProductionMode)
	}
	return nil
}

// load registers the section's defaults and env bindings, unmarshals the merged
// (default < file < env) configuration over the receiver, resolves the time
// location, and validates the result.
func (c *ApplicationConfig) load(v *viper.Viper) error {
	if err := bindEnvDefaults(v, "application", defaultApplicationConfig()); err != nil {
		return fmt.Errorf("bind config %q: %w", "application", err)
	}

	var wrap struct {
		Application ApplicationConfig `mapstructure:"application"`
	}
	if err := v.Unmarshal(&wrap); err != nil {
		return fmt.Errorf("parse config %q: %w", "application", err)
	}
	*c = wrap.Application

	loc, err := c.TimeZone.Location()
	if err != nil {
		return err
	}
	c.TimeLocation = loc
	return c.validate()
}

// defaultApplicationConfig returns the built-in application defaults.
func defaultApplicationConfig() *ApplicationConfig {
	tz := ApplicationTimeZone{
		Name: defaultApplicationTimeZoneName,
		FixedZone: ApplicationFixedZone{
			Name:   defaultApplicationFixedZoneName,
			Offset: defaultApplicationFixedZoneOffset,
		},
	}
	loc, err := tz.Location()
	if err != nil {
		// The default zone name is embedded via tzdata and should always
		// resolve; fall back to the fixed zone (which never errors) so
		// TimeLocation is never nil.
		loc = time.FixedZone(tz.FixedZone.Name, tz.FixedZone.Offset)
	}
	config := &ApplicationConfig{
		Name:         defaultApplicationName,
		Mode:         ApplicationDevelopmentMode,
		TimeZone:     tz,
		TimeLocation: loc,
	}
	return config
}

// Application is the committed application configuration, initialised to the
// defaults and replaced by Load.
var Application = defaultApplicationConfig()

// init applies the default time zone immediately and registers the loader that
// parses the application section and commits it (and time.Local) on Load.
func init() {
	time.Local = Application.TimeLocation
	register(func(v *viper.Viper) (commit, error) {
		c := &ApplicationConfig{}
		if err := c.load(v); err != nil {
			return nil, err
		}
		return func() error { Application = c; time.Local = c.TimeLocation; return nil }, nil
	})
}

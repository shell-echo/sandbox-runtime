package logger

// Options is the full logger configuration: the minimum Level, whether to
// attach the caller source to each record, and the optional rotating-file sink.
// It is typically populated from application config.
type Options struct {
	Level     Level `mapstructure:"level"`
	AddSource bool  `mapstructure:"add_source"`
	File      File  `mapstructure:"file"`
}

// Validate checks both the level and the file configuration, returning the
// first error found.
func (o *Options) Validate() error {
	if err := o.Level.Validate(); err != nil {
		return err
	}
	if err := o.File.Validate(); err != nil {
		return err
	}
	return nil
}

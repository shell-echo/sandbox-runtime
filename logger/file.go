package logger

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// File configures the optional rotating-file sink. The fields mirror
// lumberjack's options: MaxSize is in megabytes, MaxBackups is the number of
// old files to keep, MaxAge is in days, and Compress gzips rotated files. An
// empty Name disables file logging.
type File struct {
	Name       string `mapstructure:"name"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

// Validate checks the file configuration and, on success, normalises Name in
// place with filepath.Clean. An empty Name is valid (file logging off).
// Parent-directory escapes are rejected per path segment (so dots inside a
// filename such as "app..2.log" remain allowed), and the numeric fields must be
// within their sensible bounds.
func (f *File) Validate() error {
	if f.Name == "" {
		return nil
	}
	cleaned := filepath.Clean(f.Name)
	for _, seg := range strings.Split(cleaned, string(filepath.Separator)) {
		if seg == ".." {
			return fmt.Errorf("logger.file.name %q must not contain parent references", f.Name)
		}
	}
	if f.MaxSize <= 0 {
		return errors.New("logger.file.max_size must be greater than 0")
	}
	if f.MaxBackups < 0 {
		return errors.New("logger.file.max_backups must be greater than or equal to 0")
	}
	if f.MaxAge < 0 {
		return errors.New("logger.file.max_age must be greater than or equal to 0")
	}
	f.Name = cleaned
	return nil
}

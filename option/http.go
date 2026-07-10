// Package option holds small, reusable configuration value types shared across
// packages (config, server), independent of any concrete subsystem.
package option

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// HTTP configures an HTTP listener.
type HTTP struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// Validate checks the listener configuration: the port must be in range and the
// host must be free of whitespace.
func (o *HTTP) Validate() error {
	if o.Host != "" && strings.ContainsAny(o.Host, " \t\n\r") {
		return fmt.Errorf("host contains whitespace: %q", o.Host)
	}
	if o.Port <= 0 || o.Port > 65535 {
		return fmt.Errorf("port out of range: %d", o.Port)
	}
	return nil
}

// Addr returns the host:port listen address.
func (o *HTTP) Addr() string {
	return net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
}

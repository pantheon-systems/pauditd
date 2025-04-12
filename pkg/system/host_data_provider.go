// Package system provides utilities for interacting with system-level data.
package system

import (
	"os"
)

const (
	hostnameEnv string = "HOSTNAME"
)

// GetHostname retrieves the hostname of the system. If no hostname
// is available, it returns an empty string.
func GetHostname() string {
	var err error

	host, ok := os.LookupEnv(hostnameEnv)
	if !ok {
		host, err = os.Hostname()
		if err != nil {
			return ""
		}
	}

	return host
}

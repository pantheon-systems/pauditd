package system

import (
	"os"
)

const (
	hostnameEnv string = "HOSTNAME"
)

// GetHostname retrieves the hostname of the system, if no hostname
// is available we return empty string
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

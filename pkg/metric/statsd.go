// Package metric provides utilities for configuring and interacting with the StatsD client.
package metric

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pantheon-systems/pauditd/pkg/system"
	"github.com/spf13/viper"
	statsd "gopkg.in/alexcesaro/statsd.v2"
)

const (
	defaultStatsdAddress    = ":8125"
	defaultStatsdSampleRate = 0.5
)

var client *statsd.Client

// Shutdown closes the StatsD client and releases resources.
func Shutdown() {
	client.Close()
	client = nil
}

// GetClient returns the current StatsD client instance.
func GetClient() *statsd.Client {
	return client
}

// SetConfigDefaults sets default configuration values for the metrics system.
func SetConfigDefaults(config *viper.Viper) {
	config.SetDefault("metrics.enabled", false)
	config.SetDefault("metrics.address", defaultStatsdAddress)
	config.SetDefault("metrics.sample_rate", defaultStatsdSampleRate)
}

// Configure initializes the StatsD client based on the provided configuration.
// It returns an error if the configuration is invalid.
func Configure(config *viper.Viper) error {
	var err error
	var statsAddress string
	var statsSampleRate float32
	statsEnabled := false

	if config.GetBool("metrics.enabled") {
		statsEnabled = true
		statsAddress = config.GetString("metrics.address")

		sampleRate, err := strconv.ParseFloat(config.GetString("metrics.sample_rate"), 32)
		if err != nil {
			return err
		}
		statsSampleRate = float32(sampleRate)
	}

	hostname := system.GetHostname()
	simpleHostName := strings.Split(hostname, ".")[0]
	statsPrefix := fmt.Sprintf("pauditd.%s", simpleHostName)
	client, err = statsd.New(
		statsd.Prefix(statsPrefix),
		statsd.Mute(!statsEnabled),
		statsd.Address(statsAddress),
		statsd.SampleRate(statsSampleRate),
	)

	return err
}

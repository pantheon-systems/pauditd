// Package main is the entry point for the pauditd application.
// It sets up configuration, audit rules, and processes audit events.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"os/exec"
	"strings"

	"github.com/pantheon-systems/pauditd/pkg/logger"
	"github.com/pantheon-systems/pauditd/pkg/marshaller"
	"github.com/pantheon-systems/pauditd/pkg/metric"
	"github.com/pantheon-systems/pauditd/pkg/output"
	"github.com/pantheon-systems/pauditd/pkg/parser"
	"github.com/spf13/viper"
)

type executor func(string, ...string) error

func lExec(s string, a ...string) error {
	return exec.Command(s, a...).Run()
}

func loadConfig(configFile string) (*viper.Viper, error) {
	config := viper.New()
	config.SetConfigFile(configFile)

	config.SetDefault("events.min", 1300)
	config.SetDefault("events.max", 1399)
	config.SetDefault("message_tracking.enabled", true)
	config.SetDefault("message_tracking.log_out_of_order", false)
	config.SetDefault("message_tracking.max_out_of_order", 500)
	config.SetDefault("output.syslog.enabled", false)
	config.SetDefault("output.syslog.priority", int(syslog.LOG_LOCAL0|syslog.LOG_WARNING))
	config.SetDefault("output.syslog.tag", "pauditd")
	config.SetDefault("output.syslog.attempts", "3")
	config.SetDefault("log.flags", 0)
	config.SetDefault("parser.enable_uid_caching", "false")
	config.SetDefault("parser.password_file_path", "/etc/passwd")

	metric.SetConfigDefaults(config)

	if err := config.ReadInConfig(); err != nil {
		return nil, err
	}

	logger.Configure(config.GetInt("log.flags"))

	return config, nil
}

func setRules(config *viper.Viper, e executor) error {
	// Clear existing rules
	if err := e("auditctl", "-D"); err != nil {
		return fmt.Errorf("failed to flush existing audit rules. Error: %s", err)
	}

	logger.Info("Flushed existing audit rules")

	// Add ours in
	if rules := config.GetStringSlice("rules"); len(rules) != 0 {
		for i, v := range rules {
			// Skip rules with no content
			if v == "" {
				continue
			}

			if err := e("auditctl", strings.Fields(v)...); err != nil {
				return fmt.Errorf("failed to add rule #%d. Error: %s", i+1, err)
			}

			logger.Info("Added audit rule #%d\n", i+1)
		}
	} else {
		return errors.New("no audit rules found")
	}

	return nil
}

func createOutput(config *viper.Viper) (*output.AuditWriter, error) {
	var writer *output.AuditWriter
	var err error
	enabledCount := 0

	for _, auditWriterName := range output.GetAvailableAuditWriters() {
		configName := "output." + auditWriterName + ".enabled"
		if config.GetBool(configName) {
			enabledCount++
			writer, err = output.CreateAuditWriter(auditWriterName, config)
			if err != nil {
				return nil, err
			}
		}
	}

	if enabledCount > 1 {
		return nil, errors.New("only one output can be enabled at a time")
	}

	if writer == nil {
		return nil, errors.New("no outputs were configured")
	}

	return writer, nil
}

func createFilters(config *viper.Viper) ([]marshaller.AuditFilter, error) {
	var ok bool

	fs := config.Get("filters")
	filters := []marshaller.AuditFilter{}

	if fs == nil {
		return filters, nil
	}

	ft, ok := fs.([]interface{})
	if !ok {
		return filters, fmt.Errorf("could not parse filters object")
	}

	for i, f := range ft {
		f2, ok := f.(map[string]interface{})
		if !ok {
			return filters, fmt.Errorf("could not parse filter %d; '%+v'", i+1, f)
		}
		af, err := marshaller.NewAuditFilter(i+1, f2)
		if err != nil {
			return filters, err
		}
		filters = append(filters, *af)
	}

	return filters, nil
}

func main() {
	configFile := flag.String("config", "", "Config file location")

	flag.Parse()

	if *configFile == "" {
		logger.Error("A config file must be provided")
		flag.Usage()
		os.Exit(1)
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	err = metric.Configure(config)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	defer metric.Shutdown()

	// output needs to be created before anything that write to stdout
	writer, err := createOutput(config)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	if err := setRules(config, lExec); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	filters, err := createFilters(config)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	nlClient, err := NewNetlinkClient(config.GetInt("socket_buffer.receive"))
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	if config.GetBool("parser.enable_uid_caching") {
		logger.Info("Enabling uid/uname caching")
		path := config.GetString("parser.password_file_path")
		parser.ActiveUsernameResolver = parser.NewCachingUsernameResolver(path)
	}

	marshaller := marshaller.NewAuditMarshaller(
		writer,
		uint16(config.GetInt("events.min")),
		uint16(config.GetInt("events.max")),
		config.GetBool("message_tracking.enabled"),
		config.GetBool("message_tracking.log_out_of_order"),
		config.GetInt("message_tracking.max_out_of_order"),
		filters,
	)

	logger.Info("Started processing events in the range [%d, %d]\n", config.GetInt("events.min"), config.GetInt("events.max"))

	// Main loop. Get data from netlink and send it to the json lib for processing
	for {
		msg, err := nlClient.Receive()
		timing := metric.GetClient().NewTiming() // measure latency from recipt of message
		if err != nil {
			if err.Error() == "no buffer space available" {
				metric.GetClient().Increment("messages.netlink_dropped")
			}
			logger.Error("Error during message receive: %+v\n", err)
			continue
		}

		metric.GetClient().Increment("messages.total")
		if msg == nil {
			continue
		}

		marshaller.Consume(msg)
		timing.Send("latency")
	}
}

package main

import (
	"errors"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/pantheon-systems/pauditd/pkg/marshaller"
	"github.com/pantheon-systems/pauditd/pkg/metric"
	"github.com/pantheon-systems/pauditd/pkg/output"
	"github.com/pantheon-systems/pauditd/pkg/parser"
	"github.com/pantheon-systems/pauditd/pkg/slog"
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

	slog.Configure(config.GetInt("log.flags"))

	return config, nil
}

func setRules(config *viper.Viper, e executor) error {
	// Clear existing rules
	if err := e("auditctl", "-D"); err != nil {
		return fmt.Errorf("Failed to flush existing audit rules. Error: %s", err)
	}

	slog.Info.Println("Flushed existing audit rules")

	// Add ours in
	if rules := config.GetStringSlice("rules"); len(rules) != 0 {
		for i, v := range rules {
			// Skip rules with no content
			if v == "" {
				continue
			}

			if err := e("auditctl", strings.Fields(v)...); err != nil {
				return fmt.Errorf("Failed to add rule #%d. Error: %s", i+1, err)
			}

			slog.Info.Printf("Added audit rule #%d\n", i+1)
		}
	} else {
		return errors.New("No audit rules found")
	}

	return nil
}

func createOutput(config *viper.Viper) (*output.AuditWriter, error) {
	var writer *output.AuditWriter
	var err error
	enabledCount := 0

	for _, auditWriterName := range output.GetAvailableAuditWriters() {
		configName := "output." + auditWriterName + ".enabled"
		if config.GetBool(configName) == true {
			enabledCount++
			writer, err = output.CreateAuditWriter(auditWriterName, config)
			if err != nil {
				return nil, err
			}
		}
	}

	if enabledCount > 1 {
		return nil, errors.New("Only one output can be enabled at a time")
	}

	if writer == nil {
		return nil, errors.New("No outputs were configured")
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
		return filters, fmt.Errorf("Could not parse filters object")
	}

	for i, f := range ft {
		f2, ok := f.(map[string]interface{})
		if !ok {
			return filters, fmt.Errorf("Could not parse filter %d; '%+v'", i+1, f)
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
		slog.Error.Println("A config file must be provided")
		flag.Usage()
		os.Exit(1)
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		slog.Error.Fatal(err)
	}

	err = metric.Configure(config)
	if err != nil {
		slog.Error.Fatal(err)
	}

	defer metric.Shutdown()

	// output needs to be created before anything that write to stdout
	writer, err := createOutput(config)
	if err != nil {
		slog.Error.Fatal(err)
	}

	if err := setRules(config, lExec); err != nil {
		slog.Error.Fatal(err)
	}

	filters, err := createFilters(config)
	if err != nil {
		slog.Error.Fatal(err)
	}

	recvSize := 0
	rmemMax := fetchRmemMax()
	// If the value is 0, use the default value from the config
	recvSize = rmemMax
	if rmemMax == 0 {
		recvSize = config.GetInt("socket_buffer.receive")
	}
	slog.Info.Printf("Setting the receive buffer size to %d\n", recvSize)

	nlClient, err := NewNetlinkClient(recvSize)
	if err != nil {
		slog.Error.Fatal(err)
	}

	if config.GetBool("parser.enable_uid_caching") {
		slog.Info.Println("Enabling uid/uname caching")
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

	slog.Info.Printf("Started processing events in the range [%d, %d]\n", config.GetInt("events.min"), config.GetInt("events.max"))

	//Main loop. Get data from netlink and send it to the json lib for processing
	for {
		msg, err := nlClient.Receive()
		if err != nil {
			if err.Error() == "no buffer space available" {
				metric.GetClient().Increment("messages.netlink_dropped")
			}
			slog.Error.Printf("Error during message receive: %+v\n", err)
			continue
		}
		if msg == nil {
			continue
		}
		// As soon as we have a message, spawn a goroutine to handle it and free up the main loop
		go handleMsg(msg, marshaller)
	}
}

// Fetch the max value we can set from /proc/sys/net/core/rmem_max
// This value is mounted in from the host via the kube yaml
func fetchRmemMax() int {
	var rmemMax int
	file, err := os.Open("/proc/sys/net/core/rmem_max")
	if err != nil {
		slog.Error.Println(fmt.Sprintf("Error opening rmem_max: [%v]", err))
	}
	defer file.Close()

	_, err = fmt.Fscanf(file, "%d", &rmemMax)
	if err != nil {
		slog.Error.Println(fmt.Sprintf("Error reading the rmem_max value: [%v]", err))
	}
	return rmemMax
}

func handleMsg(msg *syscall.NetlinkMessage, marshaller *marshaller.AuditMarshaller) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error.Printf("Panic occurred in handleMsg: %v", r)
		}
	}()

	timing := metric.GetClient().NewTiming() // measure latency from recipt of message
	metric.GetClient().Increment("messages.total")

	marshaller.Consume(msg)
	timing.Send("latency")
}

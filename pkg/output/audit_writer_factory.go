// Package output provides utilities for creating and managing audit writers.
package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/pantheon-systems/pauditd/pkg/logger"
	"github.com/spf13/viper"
)

// AuditWriterFactory is the that represents a function that is a audit writer factory
type AuditWriterFactory func(conf *viper.Viper) (*AuditWriter, error)

var auditWriterFactories = make(map[string]AuditWriterFactory)

// register adds the audit writer type to the factory
// this method is internal to this package and is used
// by passing in the constructor (factory method) in
// with a string as the key. This is done in the init
// function of the file, thus creating self-registering
// output audit writer factories
func register(name string, factory AuditWriterFactory) {
	if factory == nil {
		logger.Error("Audit writer factory %s does not exist.", name)
		os.Exit(1)
	}
	_, registered := auditWriterFactories[name]
	if registered {
		logger.Info("Audit writer factory %s already registered. Ignoring.", name)
		return
	}

	auditWriterFactories[name] = factory
}

// CreateAuditWriter creates an audit writer with the type specified by the name, the
// viper config is passed down to the audit writer factory method.
// It returns an audit writer or an error
func CreateAuditWriter(auditWriterName string, config *viper.Viper) (*AuditWriter, error) {
	auditWriterFactory, ok := auditWriterFactories[auditWriterName]
	if !ok {
		availableAuditWriters := GetAvailableAuditWriters()
		return nil, fmt.Errorf("invalid audit writer name, must be one of: %s", strings.Join(availableAuditWriters, ", "))
	}

	// Run the factory with the configuration.
	return auditWriterFactory(config)
}

// GetAvailableAuditWriters returns an array of audit writer names as strings
func GetAvailableAuditWriters() []string {
	availableAuditWriters := make([]string, len(auditWriterFactories))
	for k := range auditWriterFactories {
		availableAuditWriters = append(availableAuditWriters, k)
	}
	return availableAuditWriters
}

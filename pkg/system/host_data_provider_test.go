package system_test

import (
	"os"
	"testing"

	"github.com/pantheon-systems/pauditd/pkg/system"
	"github.com/stretchr/testify/assert"
)

func Test_GetHostnameWithEnvVar(t *testing.T) {
	testName := "test-node-name"

	if err := os.Setenv("HOSTNAME", testName); err != nil {
		t.Errorf("Failed to set environment variable: %v", err)
	}

	hostname := system.GetHostname()

	assert.Equal(t, testName, hostname)
}

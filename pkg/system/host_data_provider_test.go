package system_test

import (
	"github.com/pantheon-systems/pauditd/pkg/system"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetHostnameWithEnvVar(t *testing.T) {
	testName := "test-node-name"

	os.Setenv("NODENAME", testName)

	hostname := system.GetHostname()

	assert.Equal(t, testName, hostname)
}

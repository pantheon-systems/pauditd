package system_test

import (
	"os"
	"testing"

	"github.com/pantheon-systems/pauditd/pkg/system"

	"github.com/stretchr/testify/assert"
)

func Test_GetHostnameWithEnvVar(t *testing.T) {
	testName := "test-node-name"

	os.Setenv("HOSTNAME", testName)

	hostname := system.GetHostname()

	assert.Equal(t, testName, hostname)
}

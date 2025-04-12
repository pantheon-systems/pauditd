package system_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pantheon-systems/pauditd/pkg/system"
)

func Test_GetHostnameWithEnvVar(t *testing.T) {
	testName := "test-node-name"

	os.Setenv("HOSTNAME", testName)

	hostname := system.GetHostname()

	assert.Equal(t, testName, hostname)
}

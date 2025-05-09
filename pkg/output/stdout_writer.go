package output

import (
	"fmt"
	"os"

	"github.com/pantheon-systems/pauditd/pkg/logger"
	"github.com/spf13/viper"
)

func init() {
	register("stdout", newStdOutWriter)
}

func newStdOutWriter(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.stdout.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("output attempts for stdout must be at least 1, %v provided", attempts)
	}

	// info logger is no longer stdout
	logger.SetOutput(os.Stderr, "info")

	return NewAuditWriter(os.Stdout, attempts), nil
}

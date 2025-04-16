package output

import (
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/pantheon-systems/pauditd/pkg/slog"
	"github.com/spf13/viper"
)

func init() {
	register("file", newFileWriter)
}

func newFileWriter(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.file.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("output attempts for file must be at least 1, %d provided", attempts)
	}

	mode := config.GetInt("output.file.mode")
	if mode <= 0 {
		return nil, fmt.Errorf("output file mode should be greater than 0000")
	}

	path := config.GetString("output.file.path")
	if path == "" {
		return nil, fmt.Errorf("output file path cannot be empty")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(mode))
	if err != nil {
		return nil, fmt.Errorf("failed to open output file. Error: %v", err)
	}

	if err := file.Chmod(os.FileMode(mode)); err != nil {
		return nil, fmt.Errorf("failed to set file permissions. Error: %s", err)
	}

	uname := config.GetString("output.file.user")
	u, err := user.Lookup(uname)
	if err != nil {
		return nil, fmt.Errorf("could not find uid for user %s. Error: %s", uname, err)
	}

	gname := config.GetString("output.file.group")
	g, err := user.LookupGroup(gname)
	if err != nil {
		return nil, fmt.Errorf("could not find gid for group %s. Error: %s", gname, err)
	}

	uid, err := strconv.ParseInt(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("found uid could not be parsed. Error: %s", err)
	}

	gid, err := strconv.ParseInt(g.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("found gid could not be parsed. Error: %s", err)
	}

	if err = file.Chown(int(uid), int(gid)); err != nil {
		return nil, fmt.Errorf("could not chown output file. Error: %s", err)
	}

	writer := NewAuditWriter(file, attempts)
	go handleLogRotation(config, writer)
	return writer, nil
}

func handleLogRotation(config *viper.Viper, writer *AuditWriter) {
	// Re-open our log file. This is triggered by a USR1 signal and is meant to be used upon log rotation
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGUSR1)

	for range sigc {
		newWriter, err := newFileWriter(config)
		if err != nil {
			slog.Error.Fatalln("Error re-opening log file. Exiting.")
		}

		oldFile, ok := writer.w.(*os.File)
		if !ok {
			slog.Error.Fatalln("writer.w is not of type *os.File. Exiting.")
		}

		if err := oldFile.Close(); err != nil {
			slog.Error.Printf("failed to close old file: %v", err)
		}
		writer.w = newWriter.w
	}
}

package output

import (
	"os"
	"os/user"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func Test_newFileWriter(t *testing.T) {
	testCases := []struct {
		name          string
		config        *viper.Viper
		expectedError string
	}{
		{
			name: "attempts error",
			config: func() *viper.Viper {
				c := viper.New()
				c.Set("output.file.attempts", 0)
				return c
			}(),
			expectedError: "output attempts for file must be at least 1, 0 provided",
		},
		{
			name: "failure to create/open file",
			config: func() *viper.Viper {
				c := viper.New()
				c.Set("output.file.attempts", 1)
				c.Set("output.file.path", "/do/not/exist/please")
				c.Set("output.file.mode", 0o644)
				return c
			}(),
			expectedError: "failed to open output file. Error: open /do/not/exist/please: no such file or directory",
		},
		{
			name: "chmod error",
			config: func() *viper.Viper {
				c := viper.New()
				c.Set("output.file.attempts", 1)
				c.Set("output.file.path", path.Join(os.TempDir(), "pauditd.test.log"))
				c.Set("output.file.mode", 0)
				return c
			}(),
			expectedError: "output file mode should be greater than 0000",
		},
		{
			name: "uid error",
			config: func() *viper.Viper {
				c := viper.New()
				c.Set("output.file.attempts", 1)
				c.Set("output.file.path", path.Join(os.TempDir(), "pauditd.test.log"))
				c.Set("output.file.mode", 0o644)
				c.Set("output.file.user", "nonexistentuser")
				return c
			}(),
			expectedError: "could not find uid for user nonexistentuser. Error: user: unknown user nonexistentuser",
		},
		{
			name: "gid error",
			config: func() *viper.Viper {
				c := viper.New()
				c.Set("output.file.attempts", 1)
				c.Set("output.file.path", path.Join(os.TempDir(), "pauditd.test.log"))
				c.Set("output.file.mode", 0o644)
				c.Set("output.file.user", "root")
				c.Set("output.file.group", "nonexistentgroup")
				return c
			}(),
			expectedError: "could not find gid for group nonexistentgroup. Error: group: unknown group nonexistentgroup",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := newFileWriter(tc.config)
			assert.Error(t, err)
			assert.EqualError(t, err, tc.expectedError)
			assert.Nil(t, w)
		})
	}
}

func Test_fileRotationAllGoodFile(t *testing.T) {
	uid := os.Getuid()
	gid := os.Getgid()
	u, _ := user.LookupId(strconv.Itoa(uid))
	g, _ := user.LookupGroupId(strconv.Itoa(gid))

	// travis-ci is silly
	if u.Username == "" {
		u.Username = g.Name
	}

	// all good file
	c := viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "pauditd.test.log"))
	c.Set("output.file.mode", 0o644)
	c.Set("output.file.user", u.Username)
	c.Set("output.file.group", g.Name)
	w, err := newFileWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &os.File{}, w.w)

	// we must wait for the log rotation method to listen
	// for the signal, without this timeout we send the syscall.Kill
	// to the goroutine and nothing will be listening yet
	time.Sleep(10 * time.Millisecond)

	// File rotation
	if err := os.Rename(
		path.Join(os.TempDir(), "pauditd.test.log"),
		path.Join(os.TempDir(), "pauditd.test.log.rotated"),
	); err != nil {
		t.Errorf("Failed to rename file: %v", err)
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Errorf("Failed to send signal: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	_, err = os.Stat(path.Join(os.TempDir(), "pauditd.test.log"))
	assert.Nil(t, err)
}

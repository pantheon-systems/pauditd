package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path"
	"strconv"
	"syscall"
	"testing"

	"github.com/pantheon-systems/pauditd/pkg/logger"
	"github.com/pantheon-systems/pauditd/pkg/marshaller"
	"github.com/pantheon-systems/pauditd/pkg/metric"
	"github.com/pantheon-systems/pauditd/pkg/output"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type Logline struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Msg     string `json:"msg"`
	App     string `json:"app"`
	Version string `json:"version"`
}

var logline Logline

func Test_loadConfig(t *testing.T) {
	file := createTempFile(t, "defaultValues.test.yaml", "")
	defer func() {
		if err := os.Remove(file); err != nil {
			logger.Error("Failed to remove file:", err)
		}
	}()

	// defaults
	config, err := loadConfig(file)
	assert.Equal(t, 1300, config.GetInt("events.min"), "events.min should default to 1300")
	assert.Equal(t, 1399, config.GetInt("events.max"), "events.max should default to 1399")
	assert.Equal(t, true, config.GetBool("message_tracking.enabled"), "message_tracking.enabled should default to true")
	assert.Equal(t, false, config.GetBool("message_tracking.log_out_of_order"), "message_tracking.log_out_of_order should default to false")
	assert.Equal(t, 500, config.GetInt("message_tracking.max_out_of_order"), "message_tracking.max_out_of_order should default to 500")
	assert.Equal(t, false, config.GetBool("output.syslog.enabled"), "output.syslog.enabled should default to false")
	assert.Equal(t, 132, config.GetInt("output.syslog.priority"), "output.syslog.priority should default to 132")
	assert.Equal(t, "pauditd", config.GetString("output.syslog.tag"), "output.syslog.tag should default to pauditd")
	assert.Equal(t, 3, config.GetInt("output.syslog.attempts"), "output.syslog.attempts should default to 3")
	assert.Equal(t, 0, config.GetInt("log.flags"), "log.flags should default to 0")
	assert.Nil(t, err)

	// parse error
	file = createTempFile(t, "defaultValues.test.yaml", "this is bad")
	config, err = loadConfig(file)
	assert.EqualError(t, err, "While parsing config: yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `this is...` into map[string]interface {}")
	assert.Nil(t, config)
}

func Test_setRules(t *testing.T) {
	defer resetLogger()

	// fail to flush rules
	config := viper.New()

	err := setRules(config, func(_ string, a ...string) error {
		// auditctl
		if a[0] == "-D" {
			return errors.New("testing")
		}
		return nil
	})

	assert.EqualError(t, err, "failed to flush existing audit rules. Error: testing")

	// fail on 0 rules
	err = setRules(config, func(_ string, _ ...string) error { return nil })
	assert.EqualError(t, err, "no audit rules found")

	// failure to set rule
	r := 0
	config.Set("rules", []string{"-a -1 -2", "", "-a -3 -4"})
	err = setRules(config, func(_ string, a ...string) error {
		if a[0] != "-D" {
			return errors.New("testing rule")
		}
		r++
		return nil
	})

	assert.Equal(t, 1, r, "Wrong number of rule set attempts")
	assert.EqualError(t, err, "failed to add rule #1. Error: testing rule")

	// properly set rules
	r = 0
	err = setRules(config, func(_ string, a ...string) error {
		// Skip the flush rules
		if a[0] != "-a" {
			return nil
		}

		if (a[1] == "-1" && a[2] == "-2") || (a[1] == "-3" && a[2] == "-4") {
			r++
		}

		return nil
	})

	assert.Equal(t, 2, r, "Wrong number of correct rule set attempts")
	assert.Nil(t, err)
}

func Test_createOutput(t *testing.T) {
	// no outputs
	c := viper.New()
	w, err := createOutput(c)
	assert.EqualError(t, err, "no outputs were configured")
	assert.Nil(t, w)

	// multiple outputs
	uid := os.Getuid()
	gid := os.Getgid()
	u, _ := user.LookupId(strconv.Itoa(uid))
	g, _ := user.LookupGroupId(strconv.Itoa(gid))

	// travis-ci is silly
	if u.Username == "" {
		u.Username = g.Name
	}

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := l.Close(); err != nil {
			t.Errorf("Failed to close listener: %v", err)
		}
	}()

	c = viper.New()
	c.Set("output.syslog.enabled", true)
	c.Set("output.syslog.attempts", 1)
	c.Set("output.syslog.network", "tcp")
	c.Set("output.syslog.address", l.Addr().String())

	c.Set("output.file.enabled", true)
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "pauditd.test.log"))
	c.Set("output.file.mode", 0o644)
	c.Set("output.file.user", u.Username)
	c.Set("output.file.group", g.Name)

	w, err = createOutput(c)
	assert.EqualError(t, err, "only one output can be enabled at a time")
	assert.Nil(t, w)
}

func Test_createFilters(t *testing.T) {
	lb, elb := hookLogger()
	defer resetLogger()

	// no filters
	c := viper.New()
	f, err := createFilters(c)
	assert.Nil(t, err)
	assert.Empty(t, f)

	// Bad outer filter value
	c = viper.New()
	c.Set("filters", 1)
	f, err = createFilters(c)
	assert.EqualError(t, err, "could not parse filters object")
	assert.Empty(t, f)

	// Bad inner filter value
	c = viper.New()
	rf := make([]interface{}, 0)
	rf = append(rf, "bad filter definition")
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "could not parse filter 1; 'bad filter definition'")
	assert.Empty(t, f)

	// Bad message type - string
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": "bad message type"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`message_type` in filter 1 could not be parsed; Value: `bad message type`; Error: strconv.ParseUint: parsing \"bad message type\": invalid syntax")
	assert.Empty(t, f)

	// Bad message type - unknown
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": false})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`message_type` in filter 1 could not be parsed; Value: `false`")
	assert.Empty(t, f)

	// Bad regex - not string
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"regex": false})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`regex` in filter 1 could not be parsed; Value: `false`")
	assert.Empty(t, f)

	// Bad regex - un-parse-able
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"regex": "["})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`regex` in filter 1 could not be parsed; Value: `[`; Error: error parsing regexp: missing closing ]: `[`")
	assert.Empty(t, f)

	// Bad syscall - not string or int
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"syscall": []string{}})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`syscall` in filter 1 could not be parsed; Value: `[]`")
	assert.Empty(t, f)

	// Bad key - not string
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"key": []string{}})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`key` in filter 1 could not be parsed; Value: `[]`")
	assert.Empty(t, f)

	// Missing regex
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"syscall": "1", "message_type": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "filter 1 is missing the `regex` entry")
	assert.Empty(t, f)

	// Missing message_type
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"syscall": "1", "regex": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "filter 1 is missing either the `key` entry or `syscall` and `message_type` entry")
	assert.Empty(t, f)

	// Missing syscall and not a rule key filter (message type is set)
	lb.Reset()
	elb.Reset()
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": "1", "regex": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.Nil(t, err)
	assert.NotEmpty(t, f)
	assert.Equal(t, "", f[0].Syscall)
	assert.Equal(t, uint16(1), f[0].MessageType)
	assert.Equal(t, "1", f[0].Regex.String())
	assert.Empty(t, elb.String())

	perr := json.Unmarshal([]byte(lb.Bytes()), &logline)
	if perr != nil {
		fmt.Println("Error unmarshaling logger output JSON:", perr)
	}

	assert.Equal(t, "droping syscall `` containing message type `1` matching string `1`\n", logline.Msg)

	// Missing syscall and missing key and missing message type
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"regex": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "filter 1 is missing either the `key` entry or `syscall` and `message_type` entry")
	assert.Empty(t, f)

	// Good with strings (Syscall Filter)
	lb.Reset()
	elb.Reset()
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": "1", "regex": "1", "syscall": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.Nil(t, err)
	assert.NotEmpty(t, f)
	assert.Equal(t, "1", f[0].Syscall)
	assert.Equal(t, uint16(1), f[0].MessageType)
	assert.Equal(t, "1", f[0].Regex.String())
	assert.Empty(t, elb.String())

	perr = json.Unmarshal([]byte(lb.Bytes()), &logline)
	if perr != nil {
		fmt.Println("Error unmarshaling logger output JSON:", perr)
	}
	assert.Equal(t, "droping syscall `1` containing message type `1` matching string `1`\n", logline.Msg)

	// Good with ints (Syscall Filter)
	lb.Reset()
	elb.Reset()
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": 1, "regex": "1", "syscall": 1})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.Nil(t, err)
	assert.NotEmpty(t, f)
	assert.Equal(t, "1", f[0].Syscall)
	assert.Equal(t, uint16(1), f[0].MessageType)
	assert.Equal(t, "1", f[0].Regex.String())
	assert.Empty(t, elb.String())
	perr = json.Unmarshal([]byte(lb.Bytes()), &logline)
	if perr != nil {
		fmt.Println("Error unmarshaling logger output JSON:", perr)
	}

	assert.Equal(t, "droping syscall `1` containing message type `1` matching string `1`\n", logline.Msg)

	// Good with strings (RuleKey Filter)
	lb.Reset()
	elb.Reset()
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"key": "testkey", "regex": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.Nil(t, err)
	assert.NotEmpty(t, f)
	assert.Equal(t, "", f[0].Syscall)
	assert.Equal(t, uint16(0), f[0].MessageType)
	assert.Equal(t, "1", f[0].Regex.String())
	assert.Equal(t, "testkey", f[0].Key)
	assert.Empty(t, elb.String())

	perr = json.Unmarshal([]byte(lb.Bytes()), &logline)
	if perr != nil {
		fmt.Println("Error unmarshaling logger output JSON:", perr)
	}

	assert.Equal(t, "droping messages with key `testkey` matching string `1`\n", logline.Msg)
}

func Benchmark_MultiPacketMessage(b *testing.B) {
	cfg := viper.New()
	cfg.Set("metrics.enabled", false)
	if err := metric.Configure(cfg); err != nil {
		b.Errorf("Failed to configure metric: %v", err)
	}

	marshaller := marshaller.NewAuditMarshaller(output.NewAuditWriter(&noopWriter{}, 1), uint16(1300), uint16(1399), false, false, 1, []marshaller.AuditFilter{})

	data := make([][]byte, 6)

	//&{1300,,arch=c000003e,syscall=59,success=yes,exit=0,a0=cc4e68,a1=d10bc8,a2=c69808,a3=7fff2a700900,items=2,ppid=11552,pid=11623,auid=1000,uid=1000,gid=1000,euid=1000,suid=1000,fsuid=1000,egid=1000,sgid=1000,fsgid=1000,tty=pts0,ses=35,comm="ls",exe="/bin/ls",key=(null),1222763,1459376866.885}
	data[0] = []byte{34, 1, 0, 0, 20, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 97, 114, 99, 104, 61, 99, 48, 48, 48, 48, 48, 51, 101, 32, 115, 121, 115, 99, 97, 108, 108, 61, 53, 57, 32, 115, 117, 99, 99, 101, 115, 115, 61, 121, 101, 115, 32, 101, 120, 105, 116, 61, 48, 32, 97, 48, 61, 99, 99, 52, 101, 54, 56, 32, 97, 49, 61, 100, 49, 48, 98, 99, 56, 32, 97, 50, 61, 99, 54, 57, 56, 48, 56, 32, 97, 51, 61, 55, 102, 102, 102, 50, 97, 55, 48, 48, 57, 48, 48, 32, 105, 116, 101, 109, 115, 61, 50, 32, 112, 112, 105, 100, 61, 49, 49, 53, 53, 50, 32, 112, 105, 100, 61, 49, 49, 54, 50, 51, 32, 97, 117, 105, 100, 61, 49, 48, 48, 48, 32, 117, 105, 100, 61, 49, 48, 48, 48, 32, 103, 105, 100, 61, 49, 48, 48, 48, 32, 101, 117, 105, 100, 61, 49, 48, 48, 48, 32, 115, 117, 105, 100, 61, 49, 48, 48, 48, 32, 102, 115, 117, 105, 100, 61, 49, 48, 48, 48, 32, 101, 103, 105, 100, 61, 49, 48, 48, 48, 32, 115, 103, 105, 100, 61, 49, 48, 48, 48, 32, 102, 115, 103, 105, 100, 61, 49, 48, 48, 48, 32, 116, 116, 121, 61, 112, 116, 115, 48, 32, 115, 101, 115, 61, 51, 53, 32, 99, 111, 109, 109, 61, 34, 108, 115, 34, 32, 101, 120, 101, 61, 34, 47, 98, 105, 110, 47, 108, 115, 34, 32, 107, 101, 121, 61, 40, 110, 117, 108, 108, 41}

	//&{1309,,argc=3,a0="ls",a1="--color=auto",a2="-alF",1222763,1459376866.885}
	data[1] = []byte{73, 0, 0, 0, 29, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 97, 114, 103, 99, 61, 51, 32, 97, 48, 61, 34, 108, 115, 34, 32, 97, 49, 61, 34, 45, 45, 99, 111, 108, 111, 114, 61, 97, 117, 116, 111, 34, 32, 97, 50, 61, 34, 45, 97, 108, 70, 34}

	//&{1307,,,cwd="/home/ubuntu/src/slack-github.com/rhuber/pauditd-new",1222763,1459376866.885}
	data[2] = []byte{91, 0, 0, 0, 27, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 32, 99, 119, 100, 61, 34, 47, 104, 111, 109, 101, 47, 117, 98, 117, 110, 116, 117, 47, 115, 114, 99, 47, 115, 108, 97, 99, 107, 45, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 114, 104, 117, 98, 101, 114, 47, 103, 111, 45, 97, 117, 100, 105, 116, 45, 110, 101, 119, 34}

	//&{1302,,item=0,name="/bin/ls",inode=262316,dev=ca:01,mode=0100755,ouid=0,ogid=0,rdev=00:00,nametype=NORMAL,1222763,1459376866.885}
	data[3] = []byte{129, 0, 0, 0, 22, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 105, 116, 101, 109, 61, 48, 32, 110, 97, 109, 101, 61, 34, 47, 98, 105, 110, 47, 108, 115, 34, 32, 105, 110, 111, 100, 101, 61, 50, 54, 50, 51, 49, 54, 32, 100, 101, 118, 61, 99, 97, 58, 48, 49, 32, 109, 111, 100, 101, 61, 48, 49, 48, 48, 55, 53, 53, 32, 111, 117, 105, 100, 61, 48, 32, 111, 103, 105, 100, 61, 48, 32, 114, 100, 101, 118, 61, 48, 48, 58, 48, 48, 32, 110, 97, 109, 101, 116, 121, 112, 101, 61, 78, 79, 82, 77, 65, 76}

	//&{1302,,item=1,name="/lib64/ld-linux-x86-64.so.2",inode=396037,dev=ca:01,mode=0100755,ouid=0,ogid=0,rdev=00:00,nametype=NORMAL,1222763,1459376866.885}
	data[4] = []byte{149, 0, 0, 0, 22, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 105, 116, 101, 109, 61, 49, 32, 110, 97, 109, 101, 61, 34, 47, 108, 105, 98, 54, 52, 47, 108, 100, 45, 108, 105, 110, 117, 120, 45, 120, 56, 54, 45, 54, 52, 46, 115, 111, 46, 50, 34, 32, 105, 110, 111, 100, 101, 61, 51, 57, 54, 48, 51, 55, 32, 100, 101, 118, 61, 99, 97, 58, 48, 49, 32, 109, 111, 100, 101, 61, 48, 49, 48, 48, 55, 53, 53, 32, 111, 117, 105, 100, 61, 48, 32, 111, 103, 105, 100, 61, 48, 32, 114, 100, 101, 118, 61, 48, 48, 58, 48, 48, 32, 110, 97, 109, 101, 116, 121, 112, 101, 61, 78, 79, 82, 77, 65, 76}

	//&{1320,,,1222763,1459376866.885}
	data[5] = []byte{31, 0, 0, 0, 40, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32}

	for i := 0; i < b.N; i++ {
		for n := 0; n < len(data); n++ {
			nlen := len(data[n])
			msg := &syscall.NetlinkMessage{
				Header: syscall.NlMsghdr{
					Len:   Endianness.Uint32(data[n][0:4]),
					Type:  Endianness.Uint16(data[n][4:6]),
					Flags: Endianness.Uint16(data[n][6:8]),
					Seq:   Endianness.Uint32(data[n][8:12]),
					Pid:   Endianness.Uint32(data[n][12:16]),
				},
				Data: data[n][syscall.SizeofNlMsghdr:nlen],
			}
			marshaller.Consume(msg)
		}
	}
}

type noopWriter struct{}

func (n *noopWriter) Write(_ []byte) (int, error) {
	return 0, nil
}

func createTempFile(t *testing.T, name string, contents string) string {
	file := os.TempDir() + string(os.PathSeparator) + "pauditd." + name
	if err := os.WriteFile(file, []byte(contents), os.FileMode(0o644)); err != nil {
		t.Fatal("Failed to create temp file", err)
	}
	return file
}

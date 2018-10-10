package httptransformer

import (
	"bytes"
	"github.com/pantheon-systems/go-audit/pkg/metric"
	"github.com/spf13/viper"
	"io"
	"os"
	"testing"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestNotificationServiceTransformerRegisteration(t *testing.T) {
	_, ok := transformers["notification-service"]
	assert.True(t, ok)
}

func TestNotificationServiceTransformerTransform(t *testing.T) {
	cfg := viper.New()
	cfg.Set("metrics.enabled", false)
	metric.Configure(cfg)

	transformer := NotificationServiceTransformer{
		hostname: "test-hostname",
	}

	traceID, _ := uuid.FromString("cd4702b3-4763-11e8-917a-0242ac110002")
	body := []byte("{\"sequence\":880575,\"timestamp\":\"1524242704.387\",\"messages\":[{\"type\":1300,\"data\":\"arch=c000003e syscall=2 success=yes exit=3 a0=2201ca0 a1=c2 a2=1b6 a3=fffffffffffffcd7 items=2 ppid=9976 pid=9977 auid=4294967295 uid=10005 gid=10005 euid=10005 suid=10005 fsuid=10005 egid=10005 sgid=10005 fsgid=10005 tty=(none) ses=4294967295 comm=\\\"git\\\" exe=\\\"/usr/bin/git\\\" key=\\\"binding-file-ops\\\"\"},{\"type\":1307,\"data\":\"cwd=\\\"/srv/bindings/228d4775d2df4fc18f25a7f49b956dc8/code\\\"\"},{\"type\":1302,\"data\":\"item=0 name=\\\"/srv/bindings/228d4775d2df4fc18f25a7f49b956dc8/code/.git/\\\" inode=3411559 dev=ca:41 mode=040755 ouid=10005 ogid=10005 rdev=00:00 nametype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\"},{\"type\":1302,\"data\":\"item=1 name=\\\"/srv/bindings/228d4775d2df4fc18f25a7f49b956dc8/code/.git/index.lock\\\" inode=3411349 dev=ca:41 mode=0100644 ouid=10005 ogid=10005 rdev=00:00 nametype=CREATE cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\"},{\"type\":1327,\"data\":\"proctitle=67697400616464002D41002E\"}],\"uid_map\":{\"10005\":\"228d4775d2df4fc18f25a7f49b956dc8\",\"4294967295\":\"UNKNOWN_USER\"},\"rule_key\":\"binding-file-ops\"}\n")
	resultBody, err := transformer.Transform(traceID, body)
	result := string(resultBody)
	resultExpected := `{"topic":"binding-file-ops","attributes":{"hostname":"test-hostname", "trace_id":"cd4702b3-4763-11e8-917a-0242ac110002"},"data":{"sequence":880575,"timestamp":"1524242704.387","messages":[{"type":1300,"data":"arch=c000003e syscall=2 success=yes exit=3 a0=2201ca0 a1=c2 a2=1b6 a3=fffffffffffffcd7 items=2 ppid=9976 pid=9977 auid=4294967295 uid=10005 gid=10005 euid=10005 suid=10005 fsuid=10005 egid=10005 sgid=10005 fsgid=10005 tty=(none) ses=4294967295 comm=\"git\" exe=\"/usr/bin/git\" key=\"binding-file-ops\""},{"type":1307,"data":"cwd=\"/srv/bindings/228d4775d2df4fc18f25a7f49b956dc8/code\""},{"type":1302,"data":"item=0 name=\"/srv/bindings/228d4775d2df4fc18f25a7f49b956dc8/code/.git/\" inode=3411559 dev=ca:41 mode=040755 ouid=10005 ogid=10005 rdev=00:00 nametype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0"},{"type":1302,"data":"item=1 name=\"/srv/bindings/228d4775d2df4fc18f25a7f49b956dc8/code/.git/index.lock\" inode=3411349 dev=ca:41 mode=0100644 ouid=10005 ogid=10005 rdev=00:00 nametype=CREATE cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0"},{"type":1327,"data":"proctitle=67697400616464002D41002E"}],"uid_map":{"10005":"228d4775d2df4fc18f25a7f49b956dc8","4294967295":"UNKNOWN_USER"},"rule_key":"binding-file-ops"},"version":"1.0.0"}`

	assert.Nil(t, err)
	assert.JSONEq(t, resultExpected, result)
}

func TestNotificationServiceTransformerTransformNoRuleKeyIgnore(t *testing.T) {
	cfg := viper.New()
	cfg.Set("metrics.enabled", false)
	metric.Configure(cfg)

	transformer := NotificationServiceTransformer{
		hostname:        "test-hostname",
		noTopicToStdOut: false,
	}

	traceID, _ := uuid.FromString("cd4702b3-4763-11e8-917a-0242ac110002")
	body := []byte("test string")
	resultBody, err := transformer.Transform(traceID, body)
	assert.Nil(t, resultBody)
	assert.Nil(t, err)
}

func TestNotificationServiceTransformerTransformNoRuleKeyStdout(t *testing.T) {
	transformer := NotificationServiceTransformer{
		hostname:        "test-hostname",
		noTopicToStdOut: true,
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	traceID, _ := uuid.FromString("cd4702b3-4763-11e8-917a-0242ac110002")
	bodyOrig := "test string"
	body := []byte(bodyOrig)
	resultBody, err := transformer.Transform(traceID, body)

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	w.Close()
	os.Stdout = old // restoring the real stdout
	out := <-outC

	assert.Equal(t, bodyOrig, out)
	assert.Nil(t, resultBody)
	assert.Nil(t, err)
}

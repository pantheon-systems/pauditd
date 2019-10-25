package httptransformer

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pantheon-systems/pauditd/pkg/system"
	"github.com/spf13/viper"

	"github.com/pantheon-systems/pauditd/pkg/metric"

	uuid "github.com/satori/go.uuid"
)

// NotificationServiceTransformer transforms the body of an HTTP Writer and handles the logic
// for posting to the Pantheon Notification Service (Pub/Sub Proxy)
type NotificationServiceTransformer struct {
	hostname        string
	noTopicToStdOut bool
	extraAttr       map[string]string
}

type notification struct {
	Topic      string            `json:"topic"`
	Attributes map[string]string `json:"attributes"`
	Data       json.RawMessage   `json:"data"`
	Version    string            `json:"version"`
}

var ruleKeyRegex = regexp.MustCompile(`"rule_key":"(.*)"`)

func init() {
	Register("notification-service", NewNotificationServiceTransformer)
}

// NewNotificationServiceTransformer creates new transformer
func NewNotificationServiceTransformer(config *viper.Viper) ResponseBodyTransformer {
	extraAttr := config.GetStringMapString("output.http.notification_service_transformer.extra_attributes")

	return &NotificationServiceTransformer{
		hostname:        getHostname(),
		noTopicToStdOut: false,
		extraAttr:       extraAttr,
	}
}

// Transform takes the body and wraps the notification service structure around it
func (t NotificationServiceTransformer) Transform(traceID uuid.UUID, body []byte) ([]byte, error) {
	var err error

	matches := ruleKeyRegex.FindStringSubmatch(string(body))
	// the "(null)" case is for some rules that are set by other systems (SECCOMP, TTY)
	if len(matches) < 2 || matches[1] == "" || matches[1] == "(null)" || matches[1] == "rule_key" {
		// No topic specified, default to stdout or skip
		if t.noTopicToStdOut {
			_, err = os.Stdout.Write(body)
		}
		metric.GetClient().Increment("notif-service-transformer.topic.no-topic")
		return nil, err
	}

	metric.GetClient().Increment(fmt.Sprintf("notif-service-transformer.topic.%s", matches[1]))

	// removing the \n char at the end of the message, this is added by the
	// JSON marsharler for all the other outputs but that messes up
	// the http writer for unmarshalling on the other side
	jsonBody := body[:len(body)-1]
	if err != nil {
		return nil, err
	}

	attributes := map[string]string{
		"hostname": t.hostname,
		"trace_id": traceID.String(),
	}

	// if extraAttr contains value
	if len(t.extraAttr) > 0 {
		for key, value := range t.extraAttr {
			attributes[key] = value
		}
	}

	// we remove the last char of the body, the code that creates the
	// body is in the marsharller which adds a newline at the end of the
	// message. This works for all the other output methods but not this one
	notif := notification{
		Topic:      matches[1],
		Data:       jsonBody,
		Attributes: attributes,
		Version:    "1.0.0",
	}

	transformedBody, err := json.Marshal(notif)
	if err != nil {
		return nil, err
	}

	return transformedBody, nil
}

func getHostname() string {
	host := system.GetHostname()

	// we want to normallize the hostname,
	// only the first part
	idx := strings.Index(host, ".")
	if idx != -1 {
		host = host[:idx]
	}

	return host
}

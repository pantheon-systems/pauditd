// Package marshaller provides utilities for parsing and filtering audit messages.
package marshaller

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/pantheon-systems/pauditd/pkg/slog"
)

// FilterAction represents the action to take on an audit message (keep or drop).
type FilterAction bool

// Constants defining possible filter actions.
const (
	Keep FilterAction = false // Keep the audit message.
	Drop FilterAction = true  // Drop the audit message.
)

func (f FilterAction) String() string {
	if f == Keep {
		return "keep"
	}

	return "drop"
}

// AuditFilter represents a filter for audit messages.
type AuditFilter struct {
	MessageType uint16
	Regex       *regexp.Regexp
	Syscall     string
	Key         string
	Action      FilterAction
}

// NewAuditFilter creates a new AuditFilter based on the provided rule number and configuration object.
func NewAuditFilter(ruleNumber int, obj map[string]interface{}) (*AuditFilter, error) {
	var err error

	af, err := parse(ruleNumber, obj)
	if err != nil {
		return nil, err
	}

	if af.Regex == nil {
		return nil, fmt.Errorf("Filter %d is missing the `regex` entry", ruleNumber)
	}

	logMsg := fmt.Sprintf("%sing messages with key `%s` matching string `%s`\n", af.Action, af.Key, af.Regex.String())
	if af.Key == "" {
		if af.MessageType == 0 {
			return nil, fmt.Errorf("Filter %d is missing either the `key` entry or `syscall` and `message_type` entry", ruleNumber)
		}

		logMsg = fmt.Sprintf("%sing syscall `%v` containing message type `%v` matching string `%s`\n", af.Action, af.Syscall, af.MessageType, af.Regex.String())
	}
	slog.Info.Print(logMsg)
	return af, nil
}

func parse(ruleNumber int, obj map[string]interface{}) (*AuditFilter, error) {
	af := &AuditFilter{
		Action: Drop,
	}

	for k, v := range obj {
		var err error
		switch k {
		case "message_type":
			err = parseMessageType(ruleNumber, v, af)
		case "regex":
			err = parseRegex(ruleNumber, v, af)
		case "syscall":
			err = parseSyscall(ruleNumber, v, af)
		case "key":
			err = parseKey(ruleNumber, v, af)
		case "action":
			err = parseAction(ruleNumber, v, af)
		}
		if err != nil {
			return nil, err
		}
	}
	return af, nil
}

func parseMessageType(ruleNumber int, v interface{}, af *AuditFilter) error {
	if ev, ok := v.(string); ok {
		fv, err := strconv.ParseUint(ev, 10, 64)
		if err != nil {
			return fmt.Errorf("`message_type` in filter %d could not be parsed; Value: `%+v`; Error: %s", ruleNumber, v, err)
		}
		af.MessageType = uint16(fv)
	} else if ev, ok := v.(int); ok {
		af.MessageType = uint16(ev)
	} else {
		return fmt.Errorf("`message_type` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
	}
	return nil
}

func parseRegex(ruleNumber int, v interface{}, af *AuditFilter) error {
	re, ok := v.(string)
	if !ok {
		return fmt.Errorf("`regex` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
	}
	var err error
	if af.Regex, err = regexp.Compile(re); err != nil {
		return fmt.Errorf("`regex` in filter %d could not be parsed; Value: `%+v`; Error: %s", ruleNumber, v, err)
	}
	return nil
}

func parseSyscall(ruleNumber int, v interface{}, af *AuditFilter) error {
	if syscall, ok := v.(string); ok {
		af.Syscall = syscall
		return nil
	}
	if ev, ok := v.(int); ok {
		af.Syscall = strconv.Itoa(ev)
	} else {
		return fmt.Errorf("`syscall` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
	}
	return nil
}

func parseKey(ruleNumber int, v interface{}, af *AuditFilter) error {
	key, ok := v.(string)
	if !ok {
		return fmt.Errorf("`key` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
	}
	af.Key = key
	return nil
}

func parseAction(ruleNumber int, v interface{}, af *AuditFilter) error {
	action, ok := v.(string)
	if !ok || (action != "keep" && action != "drop") {
		return fmt.Errorf("`action` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
	}
	af.Action = Drop
	if action == "keep" {
		af.Action = Keep
	}
	return nil
}

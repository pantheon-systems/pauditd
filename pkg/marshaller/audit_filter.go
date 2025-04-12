package marshaller

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/pantheon-systems/pauditd/pkg/slog"
)

type FilterAction bool

const (
	Keep FilterAction = false
	Drop FilterAction = true
)

func (f FilterAction) String() string {
	if f == Keep {
		return "keep"
	}

	return "drop"
}

type AuditFilter struct {
	MessageType uint16
	Regex       *regexp.Regexp
	Syscall     string
	Key         string
	Action      FilterAction
}

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
	var err error
	var ok bool

	af := &AuditFilter{
		Action: Drop,
	}

	for k, v := range obj {
		switch k {
		case "message_type":
			if ev, ok := v.(string); ok {
				fv, err := strconv.ParseUint(ev, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("`message_type` in filter %d could not be parsed; Value: `%+v`; Error: %s", ruleNumber, v, err)
				}
				af.MessageType = uint16(fv)

			} else if ev, ok := v.(int); ok {
				af.MessageType = uint16(ev)
			} else {
				return nil, fmt.Errorf("`message_type` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}
		case "regex":
			re, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("`regex` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}

			if af.Regex, err = regexp.Compile(re); err != nil {
				return nil, fmt.Errorf("`regex` in filter %d could not be parsed; Value: `%+v`; Error: %s", ruleNumber, v, err)
			}
		case "syscall":
			if af.Syscall, ok = v.(string); ok {
				// All is good
			} else if ev, ok := v.(int); ok {
				af.Syscall = strconv.Itoa(ev)
			} else {
				return nil, fmt.Errorf("`syscall` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}
		case "key":
			if af.Key, ok = v.(string); !ok {
				return nil, fmt.Errorf("`key` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}
		case "action":
			var action string
			if action, ok = v.(string); !ok || (action != "keep" && action != "drop") {
				return nil, fmt.Errorf("`action` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}

			af.Action = Drop
			if action == "keep" {
				af.Action = Keep
			}
		}
	}
	return af, nil
}

package parser

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pantheon-systems/pauditd/pkg/metric"
)

const (
	// HeaderMinLength defines the minimum length of an audit header.
	HeaderMinLength = 7
	// HeaderStartPos defines the position in the audit header where the data starts.
	HeaderStartPos = 6
	// CompleteAfter defines the duration after which a message group is considered complete
	// if no additional messages are received.
	CompleteAfter = time.Second * 2
	// MaxAuditRuleKeyLength defines the maximum length of an audit rule key.
	MaxAuditRuleKeyLength = 128
	// AuditTTY defines the input on an administrative TTY.
	AuditTTY = 1319
	// AuditSyscall represents Syscall events.
	AuditSyscall = 1300
	// AuditExecve represents execve arguments.
	AuditExecve = 1309
	// AuditCwd represents the current working directory.
	AuditCwd = 1307
	// AuditSockaddr represents a sockaddr copied as a syscall argument.
	AuditSockaddr = 1306
	// TTYRuleKey is the rule key that will be used when TTY messages are detected
	TTYRuleKey = "tty"
)

// This global is not great but since parser is a package with no specific construct
// this is about the only way to inject deps
var (
	// UsernameResolver set to default non-caching
	ActiveUsernameResolver UsernameResolver
	headerEndChar          = []byte{")"[0]}
	headerSepChar          = byte(':')
	spaceChar              = byte(' ')
)

func init() {
	if ActiveUsernameResolver == nil {
		ActiveUsernameResolver = &DefaultUsernameResolver{}
	}
}

// AuditMessage represents a single audit message.
type AuditMessage struct {
	Type      uint16 `json:"type"`
	Data      string `json:"data"`
	Seq       int    `json:"-"`
	AuditTime string `json:"-"`
}

// AuditMessageGroup represents a group of related audit messages.
type AuditMessageGroup struct {
	Seq           int               `json:"sequence"`
	AuditTime     string            `json:"timestamp"`
	CompleteAfter time.Time         `json:"-"`
	Msgs          []*AuditMessage   `json:"messages"`
	UIDMap        map[string]string `json:"uid_map"`
	Syscall       string            `json:"-"`
	RuleKey       string            `json:"rule_key"`
}

// NewAuditMessageGroup creates a new message group from the details parsed from the message.
func NewAuditMessageGroup(am *AuditMessage) *AuditMessageGroup {
	// TODO: allocating 6 msgs per group is lame and we _should_ know ahead of time roughly how many we need
	amg := &AuditMessageGroup{
		Seq:           am.Seq,
		AuditTime:     am.AuditTime,
		CompleteAfter: time.Now().Add(CompleteAfter),
		UIDMap:        make(map[string]string, 2), // Usually only 2 individual uids per execve
		Msgs:          make([]*AuditMessage, 0, 6),
	}

	amg.AddMessage(am)
	return amg
}

// NewAuditMessage creates a new pauditd message from a netlink message.
func NewAuditMessage(nlm *syscall.NetlinkMessage) *AuditMessage {
	aTime, seq := parseAuditHeader(nlm)
	return &AuditMessage{
		Type:      nlm.Header.Type,
		Data:      string(nlm.Data),
		Seq:       seq,
		AuditTime: aTime,
	}
}

// Gets the timestamp and audit sequence id from a netlink message
func parseAuditHeader(msg *syscall.NetlinkMessage) (time string, seq int) {
	headerStop := bytes.Index(msg.Data, headerEndChar)
	// If the position the header appears to stop is less than the minimum length of a header, bail out
	if headerStop < HeaderMinLength {
		return
	}

	header := string(msg.Data[:headerStop])
	if header[:HeaderStartPos] == "audit(" {
		// TODO: out of range check, possibly fully binary?
		sep := strings.IndexByte(header, headerSepChar)
		time = header[HeaderStartPos:sep]
		seq, _ = strconv.Atoi(header[sep+1:])

		// Remove the header from data
		msg.Data = msg.Data[headerStop+3:]
	}

	return time, seq
}

// AddMessage adds a new message to the current message group.
func (amg *AuditMessageGroup) AddMessage(am *AuditMessage) {
	parseTimer := metric.GetClient().NewTiming()
	amg.Msgs = append(amg.Msgs, am)
	// TODO: need to find more message types that won't contain uids
	switch am.Type {
	case AuditExecve, AuditCwd, AuditSockaddr:
		// Don't map uids here
	case AuditSyscall:
		amg.findSyscall(am)
		amg.findRuleKey(am)
		amg.mapper(am)
	case AuditTTY:
		// pam_tty_audit does not supply a rule key
		amg.RuleKey = TTYRuleKey
		amg.mapper(am)
	default:
		amg.mapper(am)
	}
	parseTimer.Send("parse")
}

// Mapper finds all `uid=` occurrences in a message and adds the username to the UIDMap object
func (amg *AuditMessageGroup) mapper(am *AuditMessage) {
	data := am.Data
	start := 0
	end := 0

	uidCount := 0

	for {
		if start = strings.Index(data, "uid="); start < 0 {
			break
		}

		// Progress the start point beyon the = sign
		start += 4
		if end = strings.IndexByte(data[start:], spaceChar); end < 0 {
			// There was no ending space, maybe the uid is at the end of the line
			end = len(data) - start

			// If the end of the line is greater than 5 characters away (overflows a 16 bit uint) then it can't be a uid
			if end > 5 {
				break
			}
		}

		uid := data[start : start+end]

		// Don't bother re-adding if the existing group already has the mapping
		if _, ok := amg.UIDMap[uid]; !ok {
			amg.UIDMap[uid] = ActiveUsernameResolver.Resolve(data[start : start+end])
			uidCount++
		}

		// Find the next uid= if we have space for one
		next := start + end + 1
		if next >= len(data) {
			break
		}

		data = data[next:]
	}
}

func (amg *AuditMessageGroup) findRuleKey(am *AuditMessage) {
	ruleKey := amg.findDataField("key", MaxAuditRuleKeyLength, am.Data)
	amg.RuleKey = strings.ReplaceAll(ruleKey, "\"", "")
}

func (amg *AuditMessageGroup) findSyscall(am *AuditMessage) {
	// If the end of the line is greater than 5 characters away (overflows a 16 bit uint) then it can't be a syscall id
	amg.Syscall = amg.findDataField("syscall", 5, am.Data)
}

func (amg *AuditMessageGroup) findDataField(fieldName string, valueMaxLen int, data string) string {
	start := 0
	end := 0

	if start = strings.Index(data, fmt.Sprintf("%s=", fieldName)); start < 0 {
		return ""
	}

	// Progress the start point beyond the = sign
	start += (len(fieldName) + 1)
	if end = strings.IndexByte(data[start:], spaceChar); end < 0 {
		// There was no ending space, maybe the syscall id is at the end of the line
		end = len(data) - start
		if end > valueMaxLen {
			return ""
		}
	}

	return data[start : start+end]
}

package parser

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pantheon-systems/pauditd/pkg/metric"
)

const (
	HEADER_MIN_LENGTH         = 7               // Minimum length of an audit header
	HEADER_START_POS          = 6               // Position in the audit header that the data starts
	COMPLETE_AFTER            = time.Second * 2 // Log a message after this time or EOE
	MAX_AUDIT_RULE_KEY_LENGTH = 128

	AUDIT_TTY      = 1319 // Input on an administrative TTY
	AUDIT_SYSCALL  = 1300 // Syscall event
	AUDIT_EXECVE   = 1309 // execve arguments
	AUDIT_CWD      = 1307 // Current working directory
	AUDIT_SOCKADDR = 1306 // sockaddr copied as syscall arg

	// TTY_RULE_KEY is the rule key that will be used when TTY messages are detected
	TTY_RULE_KEY = "tty"
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

type AuditMessage struct {
	Type      uint16 `json:"type"`
	Data      string `json:"data"`
	Seq       int    `json:"-"`
	AuditTime string `json:"-"`
}

type AuditMessageGroup struct {
	Seq           int               `json:"sequence"`
	AuditTime     string            `json:"timestamp"`
	CompleteAfter time.Time         `json:"-"`
	Msgs          []*AuditMessage   `json:"messages"`
	UidMap        map[string]string `json:"uid_map"`
	Syscall       string            `json:"-"`
	RuleKeys      []string          `json:"rule_keys"`
}

// Creates a new message group from the details parsed from the message
func NewAuditMessageGroup(am *AuditMessage) *AuditMessageGroup {
	//TODO: allocating 6 msgs per group is lame and we _should_ know ahead of time roughly how many we need
	amg := &AuditMessageGroup{
		Seq:           am.Seq,
		AuditTime:     am.AuditTime,
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		UidMap:        make(map[string]string, 2), // Usually only 2 individual uids per execve
		Msgs:          make([]*AuditMessage, 0, 6),
		RuleKeys:      make([]string),
	}

	amg.AddMessage(am)
	return amg
}

// Creates a new pauditd message from a netlink message
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
	if headerStop < HEADER_MIN_LENGTH {
		return
	}

	header := string(msg.Data[:headerStop])
	if header[:HEADER_START_POS] == "audit(" {
		//TODO: out of range check, possibly fully binary?
		sep := strings.IndexByte(header, headerSepChar)
		time = header[HEADER_START_POS:sep]
		seq, _ = strconv.Atoi(header[sep+1:])

		// Remove the header from data
		msg.Data = msg.Data[headerStop+3:]
	}

	return time, seq
}

// Add a new message to the current message group
func (amg *AuditMessageGroup) AddMessage(am *AuditMessage) {
	parseTimer := metric.GetClient().NewTiming()
	amg.Msgs = append(amg.Msgs, am)
	//TODO: need to find more message types that won't contain uids
	switch am.Type {
	case AUDIT_EXECVE, AUDIT_CWD, AUDIT_SOCKADDR:
		// Don't map uids here
	case AUDIT_SYSCALL:
		amg.findSyscall(am)
		amg.findRuleKey(am)
		amg.mapUids(am)
	case AUDIT_TTY:
		// pam_tty_audit does not supply a rule key
		amg.RuleKey = TTY_RULE_KEY
		amg.mapUids(am)
	default:
		amg.mapUids(am)
	}
	parseTimer.Send("parse")
}

// Find all `uid=` occurrences in a message and adds the username to the UidMap object
func (amg *AuditMessageGroup) mapUids(am *AuditMessage) {
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
		if _, ok := amg.UidMap[uid]; !ok {
			amg.UidMap[uid] = ActiveUsernameResolver.Resolve(data[start : start+end])
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
	ruleKey := amg.findDataField("key", MAX_AUDIT_RULE_KEY_LENGTH, am.Data)

	// when multiple rule keys are specified they are seperated by the
	// unicode charicter \u0001 (\x01) and are encoded in hex which needs to
	// be converted to ascii
	if strings.ContainsAny(msg.RuleKey, "\x01") {
		metric.GetClient().Increment("messages.multikey")
		decoded, err := hex.DecodeString(ruleKey)
		if err == nil {
			ruleKey = fmt.Sprintf("%s", decoded)
		}
		keys = strings.Split(ruleKey, "\u0001")
	}

	for key := range keys {
		amg.RuleKeys = append(amg.RuleKeys, strings.Replace(key, "\"", "", -1))
	}
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

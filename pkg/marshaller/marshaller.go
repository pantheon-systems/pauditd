package marshaller

import (
	"os"
	"syscall"
	"time"

	"github.com/pantheon-systems/pauditd/pkg/metric"
	"github.com/pantheon-systems/pauditd/pkg/output"
	"github.com/pantheon-systems/pauditd/pkg/parser"
	"github.com/pantheon-systems/pauditd/pkg/slog"
)

const (
	EVENT_EOE = 1320 // End of multi packet event
)

type AuditMarshaller struct {
	msgs          map[int]*parser.AuditMessageGroup
	writer        *output.AuditWriter
	lastSeq       int
	missed        map[int]bool
	worstLag      int
	eventMin      uint16
	eventMax      uint16
	trackMessages bool
	logOutOfOrder bool
	maxOutOfOrder int
	attempts      int
	filters       map[string]map[uint16][]*AuditFilter // { syscall: { mtype: [regexp, ...] } }
}

// Create a new marshaller
func NewAuditMarshaller(w *output.AuditWriter, eventMin uint16, eventMax uint16, trackMessages, logOOO bool, maxOOO int, filters []AuditFilter) *AuditMarshaller {
	am := AuditMarshaller{
		writer:        w,
		msgs:          make(map[int]*parser.AuditMessageGroup, 5), // It is not typical to have more than 2 message groups at any given time
		missed:        make(map[int]bool, 10),
		eventMin:      eventMin,
		eventMax:      eventMax,
		trackMessages: trackMessages,
		logOutOfOrder: logOOO,
		maxOutOfOrder: maxOOO,
		filters:       make(map[string]map[uint16][]*AuditFilter),
	}

	am.processAndSetFilters(filters)
	return &am
}

// Ingests a netlink message and likely prepares it to be logged
func (a *AuditMarshaller) Consume(nlMsg *syscall.NetlinkMessage) {
	aMsg := parser.NewAuditMessage(nlMsg)

	if aMsg.Seq == 0 {
		// We got an invalid audit message, return the current message and reset
		a.flushOld()
		return
	}

	if a.trackMessages {
		a.detectMissing(aMsg.Seq)
	}

	if nlMsg.Header.Type < a.eventMin || nlMsg.Header.Type > a.eventMax {
		// Drop all audit messages that aren't things we care about or end a multi packet event
		a.flushOld()
		return
	} else if nlMsg.Header.Type == EVENT_EOE {
		// This is end of event msg, flush the msg with that sequence and discard this one
		a.completeMessage(aMsg.Seq)
		return
	}

	if val, ok := a.msgs[aMsg.Seq]; ok {
		// Use the original AuditMessageGroup if we have one
		val.AddMessage(aMsg)
	} else {
		// Create a new AuditMessageGroup
		a.msgs[aMsg.Seq] = parser.NewAuditMessageGroup(aMsg)
	}

	a.flushOld()
}

// Outputs any messages that are old enough
// This is because there is no indication of multi message events coming from kaudit
func (a *AuditMarshaller) flushOld() {
	now := time.Now()
	for seq, msg := range a.msgs {
		if msg.CompleteAfter.Before(now) || now.Equal(msg.CompleteAfter) {
			a.completeMessage(seq)
		}
	}
}

// Write a complete message group to the configured output in json format
func (a *AuditMarshaller) completeMessage(seq int) {
	var msg *parser.AuditMessageGroup
	var ok bool

	if msg, ok = a.msgs[seq]; !ok {
		//TODO: attempted to complete a missing message, log?
		return
	}

	if a.dropMessage(msg) {
		metric.GetClient().Increment("messages.filtered")
		delete(a.msgs, seq)
		return
	}

	if err := a.writer.Write(msg); err != nil {
		slog.Error.Println("Failed to write message. Error:", err)
		os.Exit(1)
	}

	delete(a.msgs, seq)
}

func (a *AuditMarshaller) dropMessage(msg *parser.AuditMessageGroup) FilterAction {
	// SyscallMessage filters are always evaluated before rule key filters, preserving
	// the original functionality first and for most for backward compatibility
	filterTimer := metric.GetClient().NewTiming()
	result := a.filterSyscallMessageType(msg) || a.filterRuleKey(msg)
	filterTimer.Send("marshaller.filter_latency")
	return result
}

func (a *AuditMarshaller) filterSyscallMessageType(msg *parser.AuditMessageGroup) FilterAction {
	syscallFilters, hasSyscall := a.filters[msg.Syscall]
	if !hasSyscall {
		// no filter found for rule key move on (fast path)
		return Keep
	}

	// for this each rule is executed for each message apart of the group
	// before moving on to the next message
	for _, msg := range msg.Msgs {
		if fg, hasFilter := syscallFilters[msg.Type]; hasFilter {
			for _, filter := range fg {
				if filter.Regex.MatchString(msg.Data) {
					return filter.Action
				}
			}
		}
	}

	return Keep
}

func (a *AuditMarshaller) filterRuleKey(msgGroup *parser.AuditMessageGroup) FilterAction {
	// we have one or more rule keys per message. We will remove the rule key if it is
	// dropped, if there are no rule keys left at the end we drop the whole message.

	retVal := Drop
	keepKeys = []string{}
	for _, ruleKey := range msgGroup.RuleKeys {
		// rule key filters are indexed in at 0 as we dont use the message type
		ruleKeyFilters, hasRuleKey := a.filters[ruleKey][0]

		if !hasRuleKey {
			// no filter found for rule key move on (fast path)
			continue
		}

		fullMessage := ""
		for _, msg := range msgGroup.Msgs {
			fullMessage += msg.Data
		}

		if runFilters(ruleKeyFilters, msg) == Drop {
			continue
		}

		keepKeys = append(keepKeys, key)
		retVal = Keep
	}

	msgGroup.RuleKeys = keepKeys

	return retVal
}

func runFilters(filters []*AuditFilter, msg string) {
	// for this each rule is evaluated against all the messages before moving on
	// to the next rule
	for _, filter := range ruleKeyFilters {
		if filter.Regex.MatchString(fullMessage) {
			return filter.Action
		}
	}

	return Keep
}

// Track sequence numbers and log if we suspect we missed a message
func (a *AuditMarshaller) detectMissing(seq int) {
	if seq > a.lastSeq+1 && a.lastSeq != 0 {
		// We likely leap frogged over a msg, wait until the next sequence to make sure
		for i := a.lastSeq + 1; i < seq; i++ {
			a.missed[i] = true
		}
	}

	for missedSeq := range a.missed {
		if missedSeq == seq {
			lag := a.lastSeq - missedSeq
			if lag > a.worstLag {
				a.worstLag = lag
			}

			if a.logOutOfOrder {
				slog.Error.Println("Got sequence", missedSeq, "after", lag, "messages. Worst lag so far", a.worstLag, "messages")
			}
			delete(a.missed, missedSeq)
		} else if seq-missedSeq > a.maxOutOfOrder {
			slog.Error.Printf("Likely missed sequence %d, current %d, worst message delay %d\n", missedSeq, seq, a.worstLag)
			delete(a.missed, missedSeq)
		}
	}

	if seq > a.lastSeq {
		// Keep track of the largest sequence
		a.lastSeq = seq
	}
}

func (a *AuditMarshaller) processAndSetFilters(filters []AuditFilter) {
	for idx, filter := range filters {
		primaryKey := filter.Syscall
		if primaryKey == "" {
			primaryKey = filter.Key
		}

		if _, ok := a.filters[primaryKey]; !ok {
			a.filters[primaryKey] = make(map[uint16][]*AuditFilter)
		}

		// if we are doing a key filter then the messageType will be 0 as it is the golang default
		// value. This means that all key filters (vs syscall,messageType filters) are stored
		// in [key][0] => []*AuditFilter
		if _, ok := a.filters[primaryKey][filter.MessageType]; !ok {
			a.filters[primaryKey][filter.MessageType] = []*AuditFilter{}
		}

		a.filters[primaryKey][filter.MessageType] = append(a.filters[primaryKey][filter.MessageType], &filters[idx])
	}
}

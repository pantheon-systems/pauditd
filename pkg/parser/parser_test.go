package parser

import (
	"syscall"
	"testing"
	"time"

	"github.com/pantheon-systems/pauditd/pkg/metric"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type TestUsernameResolver struct {
	fixtureUIDMap map[string]string
}

func (r *TestUsernameResolver) Resolve(uid string) string {
	return r.fixtureUIDMap[uid]
}

func TestAuditConstants(t *testing.T) {
	assert.Equal(t, 7, HEADER_MIN_LENGTH)
	assert.Equal(t, 6, HEADER_START_POS)
	assert.Equal(t, time.Second*2, COMPLETE_AFTER)
	assert.Equal(t, []byte{")"[0]}, headerEndChar)
}

func TestNewAuditMessage(t *testing.T) {
	msg := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1309),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:99): key=testkey hi there"),
	}

	am := NewAuditMessage(msg)
	assert.Equal(t, uint16(1309), am.Type)
	assert.Equal(t, 99, am.Seq)
	assert.Equal(t, "10000001", am.AuditTime)
	assert.Equal(t, "key=testkey hi there", am.Data)
}

func TestAuditMessageGroup_AddMessage(t *testing.T) {
	cfg := viper.New()
	cfg.Set("metrics.enabled", false)
	if err := metric.Configure(cfg); err != nil {
		t.Fatalf("Failed to configure metrics: %v", err)
	}

	ActiveUsernameResolver = &TestUsernameResolver{
		fixtureUIDMap: map[string]string{
			"0": "hi",
			"1": "nope",
		},
	}

	amg := &AuditMessageGroup{
		Seq:           1,
		AuditTime:     "ok",
		RuleKey:       "testkey",
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		UidMap:        make(map[string]string, 2),
	}

	m := &AuditMessage{
		Data: "uid=0 key=testkey things notuid=nopethisisnot",
	}

	amg.AddMessage(m)
	assert.Equal(t, 1, len(amg.Msgs), "Expected 1 message")
	assert.Equal(t, m, amg.Msgs[0], "First message was wrong")
	assert.Equal(t, 1, len(amg.UidMap), "Incorrect uid mapping count")
	assert.Equal(t, "testkey", amg.RuleKey, "Testkey did not get set")
	assert.Equal(t, "hi", amg.UidMap["0"])

	// Make sure we don't parse uids for message types that don't have them
	m = &AuditMessage{
		Type: uint16(1309),
		Data: "uid=1",
	}
	amg.AddMessage(m)
	assert.Equal(t, 2, len(amg.Msgs), "Expected 2 messages")
	assert.Equal(t, m, amg.Msgs[1], "2nd message was wrong")
	assert.Equal(t, 1, len(amg.UidMap), "Incorrect uid mapping count")

	m = &AuditMessage{
		Type: uint16(1307),
		Data: "uid=1",
	}
	amg.AddMessage(m)
	assert.Equal(t, 3, len(amg.Msgs), "Expected 2 messages")
	assert.Equal(t, m, amg.Msgs[2], "3rd message was wrong")
	assert.Equal(t, 1, len(amg.UidMap), "Incorrect uid mapping count")
}

func TestNewAuditMessageGroup(t *testing.T) {
	m := &AuditMessage{
		Type:      uint16(1300),
		Seq:       1019,
		AuditTime: "9919",
		Data:      "key=testkey Stuff is here",
	}

	amg := NewAuditMessageGroup(m)
	assert.Equal(t, 1019, amg.Seq)
	assert.Equal(t, "9919", amg.AuditTime)
	assert.Equal(t, "testkey", amg.RuleKey)
	assert.True(t, amg.CompleteAfter.After(time.Now()), "Complete after time should be greater than right now")
	assert.Equal(t, 6, cap(amg.Msgs), "Msgs capacity should be 6")
	assert.Equal(t, 1, len(amg.Msgs), "Msgs should only have 1 message")
	assert.Equal(t, 0, len(amg.UidMap), "No uids in the original message")
	assert.Equal(t, m, amg.Msgs[0], "First message should be the original")
}

func TestAuditMessageGroup_mapUids(t *testing.T) {
	ActiveUsernameResolver = &TestUsernameResolver{
		fixtureUIDMap: map[string]string{
			"0":     "hi",
			"1":     "there",
			"2":     "fun",
			"3":     "test",
			"99999": "derp",
		},
	}

	amg := &AuditMessageGroup{
		Seq:           1,
		AuditTime:     "ok",
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		UidMap:        make(map[string]string, 2),
	}

	m := &AuditMessage{
		Data: "uid=0 1uid=1 2uid=2 3uid=3 key=testkey not here 4uid=99999",
	}
	amg.mapUids(m)

	assert.Equal(t, 5, len(amg.UidMap), "Uid map is too big")
	assert.Equal(t, "hi", amg.UidMap["0"])
	assert.Equal(t, "there", amg.UidMap["1"])
	assert.Equal(t, "fun", amg.UidMap["2"])
	assert.Equal(t, "test", amg.UidMap["3"])
	assert.Equal(t, "derp", amg.UidMap["99999"])
}

func TestAuditMessageGroup_findDataFiles(t *testing.T) {
	amg := &AuditMessageGroup{}

	result := amg.findDataField("testfield", 128, "uid=0 1uid=1 2uid=2 testfield=testvalue 3uid=3 not here 4uid=99999")
	assert.Equal(t, "testvalue", result)

	result = amg.findDataField("testfield", 2, "uid=0 1uid=1 2uid=2 3uid=3 not here 4uid=99999 testfield=testvalue")
	assert.Equal(t, "", result)

	result = amg.findDataField("testfield", 128, "uid=0 1uid=1 2uid=2 3uid=3 not here 4uid=99999")
	assert.Equal(t, "", result)
}

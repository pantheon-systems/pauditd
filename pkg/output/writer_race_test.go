// +build race

package output

import (
	"encoding/json"
	"testing"

	"github.com/pantheon-systems/pauditd/pkg/parser"
)

// Tests against a race condition.
// To marshal and write JSON to its wrapped writer, `AuditWriter` was using the
// `(json.Encoder).Encode(msg)` function available in the `json` library.
// When the wrapped writer makes its own calls to the `json` marshalling functions,
// the `json` library's internal state is accessed concurrently.
// The bug was fixed by altering `AuditWriter` to marshal and write in two steps.
// https://getpantheon.atlassian.net/browse/PLAT-1210
func TestAuditWriterRace(t *testing.T) {
	messageCount := 10

	// Wrapped writer
	writer := &raceWriter{
		messages: make(chan []byte),
		cancel:   make(chan struct{}),
	}

	// Test subject
	subject := NewAuditWriter(writer, 1)

	// Deploy a worker
	go writer.runWorker()

	// Write a bunch of messages
	for i := 0; i < messageCount; i++ {
		amg := &parser.AuditMessageGroup{}
		if err := subject.Write(amg); err != nil {
			t.Error(err)
		}
	}

	// Stop worker
	close(writer.cancel)
}

type raceWriter struct {
	messages chan []byte
	cancel   chan struct{}
}

// Implement `io.Writer`
func (w raceWriter) Write(p []byte) (n int, err error) {
	w.messages <- p

	return 0, nil
}

func (w *raceWriter) runWorker() {
	for {
		select {
		case <-w.cancel:
			return
		case message := <-w.messages:

			// Call json.Marshal like HTTPWriter
			_, err := json.Marshal(message)

			if err != nil {
				panic(err)
			}
		}
	}
}

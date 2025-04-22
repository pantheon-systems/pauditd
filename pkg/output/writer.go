package output

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pantheon-systems/pauditd/pkg/logger"
	"github.com/pantheon-systems/pauditd/pkg/parser"
)

// AuditWriter is the class that encapsulates the io.Writer for output
type AuditWriter struct {
	w        io.Writer
	attempts int
}

// NewAuditWriter creates a generic auditwriter which encapsulates a io.Writer
func NewAuditWriter(w io.Writer, attempts int) *AuditWriter {
	return &AuditWriter{
		w:        w,
		attempts: attempts,
	}
}

func (a *AuditWriter) Write(msg *parser.AuditMessageGroup) (err error) {
	jsonBytes, err := json.Marshal(msg)
	if err != nil {
		return errors.New("unable to marshal JSON: " + err.Error())
	}
	jsonBytes = append(jsonBytes, '\n') // Backwards compat with `(json.Encoder).Encode()`

	for i := 0; i < a.attempts; i++ {
		_, err = a.w.Write(jsonBytes)
		if err == nil {
			break
		}

		if i != a.attempts {
			logger.Error("Failed to write message, retrying in 1 second. Error:", err)
			time.Sleep(time.Second * 1)
		}
	}

	return err
}

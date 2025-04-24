// Package logger provides logging utilities for the application from slog package,
// including support for structured logging and integration with external interfaces.
package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

var (
	infoLogger  *slog.Logger
	errorLogger *slog.Logger
	appName     = "pauditd"
	appVersion  = "dev" // overridden at build time
)

func newLogger(output io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level})).With(
		slog.String("app", appName),
		slog.String("version", appVersion),
	)
}

func init() {
	infoLogger = newLogger(os.Stdout, slog.LevelInfo)
	errorLogger = newLogger(os.Stderr, slog.LevelError)
}

// Configure sets the logging level for both info and error loggers.
func Configure(level slog.Level) {
	infoLogger = newLogger(os.Stdout, level)
	errorLogger = newLogger(os.Stderr, level)
}

// SetOutput sets the output destination for the specified logger ("info" or "error").
func SetOutput(output io.Writer, logger string) {
	if logger == "info" {
		infoLogger = newLogger(output, slog.LevelInfo)
	}
	if logger == "error" {
		errorLogger = newLogger(output, slog.LevelError)
	}
}

// Info logs an informational message using the info logger.
func Info(msg string, args ...any) {
	infoLogger.Info(msg, args...)
}

// Error logs an error message using the error logger.
func Error(msg string, args ...any) {
	errorLogger.Error(msg, args...)
}

// Wrapper wraps *slog.Logger to implement the certinel.logger interface.
type Wrapper struct {
	logger *slog.Logger
}

// Printf implements the Printf method required by certinel.logger.
func (lw *Wrapper) Printf(format string, args ...any) {
	lw.logger.Info(fmt.Sprintf(format, args...))
}

// With implements the method required to customize certinel.logger.
func (lw *Wrapper) With(attrs []any) *Wrapper {
	return &Wrapper{
		logger: lw.logger.With(attrs...),
	}
}

// GetLoggerWrapper returns a Wrapper for the info logger to implement the certinel.logger interface.
func GetLoggerWrapper() *Wrapper {
	return &Wrapper{logger: infoLogger}
}

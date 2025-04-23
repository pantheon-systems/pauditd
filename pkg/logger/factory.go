package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

var info *slog.Logger
var error *slog.Logger

func init() {
    info = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
    error = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func Configure(level slog.Level) {
    info = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
    error = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func SetOutput(output io.Writer, logger string) {

    if logger == "info" {
    info = slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelInfo}))
    }
    if logger == "error" {
    error = slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelError}))
    }
}

func Info(msg string, args ...any) {
    info.Info(msg, args...)
}

func Error(msg string, args ...any) {
    error.Error(msg, args...)
}

// LoggerWrapper wraps *slog.Logger to implement the certinel.logger interface
type LoggerWrapper struct {
    logger *slog.Logger
}

// Printf implements the Printf method required by certinel.logger
func (lw *LoggerWrapper) Printf(format string, args ...any) {
    lw.logger.Info(fmt.Sprintf(format, args...))
}

// GetLoggerWrapper returns a LoggerWrapper for the info logger
func GetLoggerWrapper() *LoggerWrapper {
    return &LoggerWrapper{logger: info}
}

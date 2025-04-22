package logger

import (
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

func Info(msg string, args ...any) {
    info.Info(msg, args...)
}

func Error(msg string, args ...any) {
    error.Error(msg, args...)
}
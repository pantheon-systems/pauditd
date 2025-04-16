package slog

import (
	"log/slog"
	"os"
)

var Info *slog.Logger
var Error *slog.Logger

func init() {
    Info = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
    Error = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func Configure(level slog.Level) {
    Info = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
    Error = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

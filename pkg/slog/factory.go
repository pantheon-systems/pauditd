// Package slog provides logging utilities for the pauditd application.
package slog

import (
	"log"
	"os"
)

var (
	// Info is the logger used for informational messages.
	Info *log.Logger
	// Error is the logger used for error messages.
	Error *log.Logger
)

func init() {
	Info = log.New(os.Stdout, "", 0)
	Error = log.New(os.Stderr, "", 0)
}

// Configure sets the logging flags for both Info and Error loggers.
func Configure(flags int) {
	Info.SetFlags(flags)
	Error.SetFlags(flags)
}

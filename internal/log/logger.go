// Package log contains functions to print different message types.
package log

import (
	"time"

	"github.com/pterm/pterm"
)

type Logger struct {
	Debug bool
}

func (l *Logger) SetDebug(value bool) {
	l.Debug = value
}

func (l Logger) Warn(msg ...any) {
	if l.Debug {
		pterm.Warning.Println(msg...)
	}
}

func (l Logger) Warnf(format string, params ...any) {
	if l.Debug {
		pterm.Warning.Printf(format, params...)
	}
}

func (l Logger) Info(msg ...any) {
	if l.Debug {
		pterm.Info.Println(msg...)
	}
}

func (l Logger) Infof(format string, params ...any) {
	if l.Debug {
		pterm.Info.Printf(format, params...)
	}
}

func (l Logger) Error(msg ...any) {
	if l.Debug {
		pterm.Error.Println(msg...)
	}
}

func (l Logger) Errorf(msg string, params ...any) {
	if l.Debug {
		pterm.Error.Printf(msg, params...)
	}
}

func (l Logger) WaitTimeout(duration time.Duration, timeoutReason string) {
	spinner, _ := pterm.DefaultSpinner.Start("Waiting for "+timeoutReason, " timeout")
	<-time.After(duration)
	spinner.Success("Timeout Reached.")
}

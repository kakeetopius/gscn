// Package log contains functions to print different message types.
package log

import (
	"os"
	"time"

	"github.com/pterm/pterm"
)

type Logger struct {
	Debug       bool
	infoWriter  pterm.PrefixPrinter
	warnWriter  pterm.PrefixPrinter
	errorWriter pterm.PrefixPrinter
}

func NewLogger(debug bool) Logger {
	infoWriter, warnWriter, errorWriter := pterm.Info, pterm.Warning, pterm.Error
	infoWriter.Writer = os.Stderr
	warnWriter.Writer = os.Stderr
	errorWriter.Writer = os.Stderr

	return Logger{
		Debug:       debug,
		infoWriter:  infoWriter,
		warnWriter:  warnWriter,
		errorWriter: errorWriter,
	}
}

func (l *Logger) SetDebug(value bool) {
	l.Debug = value
}

func (l Logger) Warn(msg ...any) {
	if l.Debug {
		l.warnWriter.Println(msg...)
	}
}

func (l Logger) Warnf(format string, params ...any) {
	if l.Debug {
		l.warnWriter.Printf(format, params...)
	}
}

func (l Logger) Info(msg ...any) {
	if l.Debug {
		l.infoWriter.Println(msg...)
	}
}

func (l Logger) Infof(format string, params ...any) {
	if l.Debug {
		l.infoWriter.Printf(format, params...)
	}
}

func (l Logger) Error(msg ...any) {
	if l.Debug {
		l.errorWriter.Println(msg...)
	}
}

func (l Logger) Errorf(msg string, params ...any) {
	if l.Debug {
		l.errorWriter.Printf(msg, params...)
	}
}

func (l Logger) WaitTimeout(duration time.Duration, timeoutReason string) {
	spinner, _ := pterm.DefaultSpinner.Start("Waiting for "+timeoutReason, " timeout")
	<-time.After(duration)
	spinner.Success("Timeout Reached.")
}

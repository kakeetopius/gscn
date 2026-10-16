// Package notify is used to send messages to a user for scan results.
package notify

import (
	"context"
	"fmt"
	"sync"

	"github.com/pterm/pterm"
)

// Notifier defines the interface for sending notification messages.
type Notifier interface {
	// Name identifies the backend notifier.
	Name() string
	// SendMessage sends a notification message and returns an error if it fails.
	SendMessage(ctx context.Context, message string) error
}

type Dispatcher struct {
	notifiers []Notifier
}

func NewDispatcher(notifiers ...Notifier) *Dispatcher {
	return new(Dispatcher{notifiers: notifiers})
}

func (d *Dispatcher) Dispatch(ctx context.Context, msg fmt.Stringer) (err error) {
	if len(d.notifiers) == 0 {
		return fmt.Errorf("error: dispatcher has no notifiers to dispatch to.")
	}
	var wg sync.WaitGroup

	multiWriter := pterm.DefaultMultiPrinter
	spinners := make([]*pterm.SpinnerPrinter, len(d.notifiers))

	for i, n := range d.notifiers {
		spinner, _ := pterm.DefaultSpinner.WithWriter(multiWriter.NewWriter()).Start("Sending results via ", n.Name())
		spinners[i] = spinner
	}
	multiWriter.Start()

	for i, n := range d.notifiers {
		wg.Add(1)
		go func(n Notifier) {
			defer wg.Done()

			err := n.SendMessage(ctx, msg.String())
			if err != nil {
				spinners[i].Fail("Error sending results via ", n.Name(), ": ", err)
			} else {
				spinners[i].Success("Results sent successfully via ", n.Name())
			}
		}(n)
	}
	wg.Wait()
	multiWriter.Stop()

	return nil
}

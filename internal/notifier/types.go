// Package notifier is used to send notifications to a user for scan results.
package notifier

import (
	"fmt"

	"github.com/spf13/viper"
)

// Notifier defines the interface for sending notification messages.
type Notifier interface {
	// SendMessage sends a notification message and returns an error if it fails.
	SendMessage(message string) error
}

// NotifierByName returns a Notifier instance based on the provided name.
// It takes a notifier type string and a Viper configuration, and returns
// the corresponding notifier or an error if the type is not supported.
func NotifierByName(s string, config *viper.Viper) (Notifier, error) {
	switch s {
	case "email":
		return EmailNotifier{
			Config: config,
		}, nil
	case "discord":
		return DiscordNotifier{
			Config: config,
		}, nil
	}
	return nil, fmt.Errorf("notifier %v not supported", s)
}

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
// the corresponding notifier properly configured using settings from viper or an error if the type is not supported.
func NotifierByName(s string, config *viper.Viper) (Notifier, error) {
	switch s {
	case "email":
		return EmailNotifier{
			FromAddress: config.GetString("notifier.email.sender_address"),
			ToAddress:   config.GetString("notifier.email.receiver_address"),
			SenderName:  config.GetString("notifier.email.sender_name"),
			AppPassword: config.GetString("notifier.email.app_password"),
		}, nil
	case "discord":
		return DiscordNotifier{
			Token:       config.GetString("notifier.discord.token"),
			ChannelID:   config.GetString("notifier.discord.channel_id"),
			ChannelName: config.GetString("notifier.discord.channel_name"),
		}, nil
	}
	return nil, fmt.Errorf("notifier %v not supported", s)
}

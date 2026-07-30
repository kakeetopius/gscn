// Package notify is used to send messages to a user for scan results.
package notify

import (
	"fmt"

	"github.com/pterm/pterm"
	"github.com/spf13/viper"
)

// Notifier defines the interface for sending notification messages.
type Notifier interface {
	// SendMessage sends a notification message and returns an error if it fails.
	SendMessage(message string) error
}

// NotifierFromConfig returns a Notifier instance based on the name given in the config
// It takes a notifier type string and a Viper configuration, and returns
// the corresponding notifier properly configured using settings from viper or an error if the type is not supported.
func NotifierFromConfig(config *viper.Viper) (Notifier, error) {
	if config == nil {
		return nil, fmt.Errorf("viper config not initialised")
	}

	notifierName := config.GetString("notifier.type")
	if notifierName == "" {
		return nil, fmt.Errorf("no notifier type set in the config file")
	}

	switch notifierName {
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
	return nil, fmt.Errorf("notifier %v not supported", notifierName)
}

func SendMessageWithNotifier(msg fmt.Stringer, notifier Notifier) error {
	spinner, err := pterm.DefaultSpinner.Start("Sending Results....")
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			spinner.Fail()
		} else {
			spinner.Success("Results Sent")
		}
	}()

	err = notifier.SendMessage(msg.String())
	if err != nil {
		return err
	}

	return nil
}

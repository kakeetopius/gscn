// Package notifier is used to send notifications to a user for scan results.
package notifier

import (
	"fmt"

	"github.com/spf13/viper"
)

type Notifier interface {
	SendMessage(message string) error
}

func NotifierByName(s string, config *viper.Viper) (Notifier, error) {
	switch s {
	case "email":
		return EmailNotifier{
			Config: config,
		}, nil
	}

	return nil, fmt.Errorf("notifier %v not supported", s)
}

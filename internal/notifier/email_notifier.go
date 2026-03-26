package notifier

import (
	"fmt"

	"github.com/spf13/viper"
	"github.com/wneessen/go-mail"
)

type EmailNotifier struct {
	Config *viper.Viper
}

func (n EmailNotifier) SendMessage(message string) error {
	messageObj := mail.NewMsg()
	config := n.Config
	username := config.GetString("notifier.email.from")
	sender := config.GetString("notifier.email.sender")
	receiver := config.GetString("notifier.email.receiver")
	password := config.GetString("notifier.email.app_password")

	if err := messageObj.To(receiver); err != nil {
		return err
	}
	if username != "" {
		if err := messageObj.FromFormat(username, sender); err != nil {
			return err
		}
	} else if err := messageObj.From(sender); err != nil {
		return err
	}

	messageObj.Subject("SCAN RESULTS FROM gscn")
	messageObj.SetBodyString(mail.TypeTextPlain, message)

	client, confErr := mail.NewClient("smtp.gmail.com", mail.WithSMTPAuth(mail.SMTPAuthPlain), mail.WithUsername(sender), mail.WithPassword(password))
	if confErr != nil {
		return fmt.Errorf("failed to create mail client %v", confErr)
	}

	if err := client.DialAndSend(messageObj); err != nil {
		return fmt.Errorf("failed to send mail: %v", err)
	}

	return nil
}

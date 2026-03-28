package notifier

import (
	"fmt"

	"github.com/spf13/viper"
	"github.com/wneessen/go-mail"
)

type EmailNotifier struct {
	Config *viper.Viper
}

// SendMessage sends an email notification with the provided message content.
// It retrieves email configuration (sender, receiver, credentials) from the notifier's config,
// constructs an email message, and sends it via Gmail's SMTP server.
// Returns an error if email construction, client creation, or sending fails.
func (n EmailNotifier) SendMessage(message string) error {
	messageObj := mail.NewMsg()
	config := n.Config
	username := config.GetString("notifier.email.from")
	if username == "" {
		username = "gscn network scanner"
	}
	sender := config.GetString("notifier.email.sender")
	if sender == "" {
		return fmt.Errorf("no sender address given")
	}
	receiver := config.GetString("notifier.email.receiver")
	if receiver == "" {
		return fmt.Errorf("no receiver address given")
	}
	password := config.GetString("notifier.email.app_password")
	if password == "" {
		return fmt.Errorf("no app password given")
	}

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

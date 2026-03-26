// Package notifier is used to send notifications to a user for scan results.
package notifier

type Notifier interface {
	SendMessage(message string) error
}

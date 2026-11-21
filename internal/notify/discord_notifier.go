package notify

import (
	"context"
	"fmt"

	"github.com/bwmarrin/discordgo"
)

type DiscordNotifier struct {
	Token     string
	ChannelID string
}

func (d DiscordNotifier) Name() string {
	return "discord"
}

func (d DiscordNotifier) SendMessage(ctx context.Context, message string) error {
	// BUG: fails when message is above 4000 characters.
	token := d.Token
	if token == "" {
		return fmt.Errorf("discord token is required to send messages to a discord server")
	}
	discord, err := discordgo.New("Bot " + token)
	if err != nil {
		return err
	}
	defer discord.Close()

	channelID := d.ChannelID
	if channelID == "" {
		return fmt.Errorf("no channel id given")
	}

	_, err = discord.ChannelMessageSend(channelID, message)
	if err != nil {
		return err
	}
	return nil
}

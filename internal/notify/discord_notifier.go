package notify

import (
	"context"
	"fmt"

	"github.com/bwmarrin/discordgo"
)

type DiscordNotifier struct {
	Token       string
	ChannelID   string
	ChannelName string
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
		channelName := d.ChannelName
		if channelName == "" {
			return fmt.Errorf("no channel id or channel name given")
		}
		channelID, err = channelIDByName(discord, channelName)
		if err != nil {
			return err
		}
	}

	_, err = discord.ChannelMessageSend(channelID, message)
	if err != nil {
		return err
	}
	return nil
}

func channelIDByName(d *discordgo.Session, channelName string) (string, error) {
	for _, g := range d.State.Guilds {
		for _, c := range g.Channels {
			if c.Name == channelName {
				return c.ID, nil
			}
		}
	}

	return "", fmt.Errorf("channel '%v' not found", channelName)
}

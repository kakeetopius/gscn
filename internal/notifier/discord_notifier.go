package notifier

import (
	"fmt"

	"github.com/bwmarrin/discordgo"
	"github.com/spf13/viper"
)

type DiscordNotifier struct {
	Config      *viper.Viper
	Token       string
	ChannelID   string
	ChannelName string
}

func (n DiscordNotifier) SendMessage(message string) error {
	// BUG: fails when message is above 4000 characters.
	token := n.Token
	if token == "" {
		return fmt.Errorf("discord token is required to send messages to a discord server")
	}
	discord, err := discordgo.New("Bot " + token)
	if err != nil {
		return err
	}
	defer discord.Close()

	channelID := n.ChannelID
	if channelID == "" {
		channelName := n.ChannelName
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

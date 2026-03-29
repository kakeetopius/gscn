package notifier

import (
	"fmt"

	"github.com/bwmarrin/discordgo"
	"github.com/spf13/viper"
)

type DiscordNotifier struct {
	Config *viper.Viper
}

func (n DiscordNotifier) SendMessage(message string) error {
	config := n.Config
	token := config.GetString("notifier.discord.token")
	if token == "" {
		return fmt.Errorf("discord token is required to send messages to a discord server")
	}
	discord, err := discordgo.New("Bot " + token)
	if err != nil {
		return err
	}
	defer discord.Close()

	channelID := config.GetString("notifier.discord.channel_id")
	if channelID == "" {
		channelName := config.GetString("notifier.discord.channel_name")
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

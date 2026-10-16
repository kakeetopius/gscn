// Package config finds and loads  and verifies the configuration
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Ports             []int           `mapstructure:"ports"`
	Notifiers         NotifiersConfig `mapstructure:"notifiers"`
	Debug             bool            `mapstructure:"debug"`
	ResultsOutputFile string          `mapstructure:"out"`
	JSONResults       bool            `mapstructure:"json"`
	JSONPretty        bool            `mapstructure:"pretty"`
	Notify            bool            `mapstructure:"notify"`

	cfg        *viper.Viper
	setupFuncs []ConfigSetupFunc
}

type NotifiersConfig struct {
	Email   EmailNotifierConfig   `mapstructure:"email"`
	Discord DiscordNotifierConfig `mapstructure:"discord"`
}

type EmailNotifierConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	SendAddress  string `mapstructure:"sender_address"`
	RecptAddress string `mapstructure:"receiver_address"`
	UserName     string `mapstructure:"user_name"`
	Password     string `mapstructure:"password"`
}

type DiscordNotifierConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	Token       string `mapstructure:"token"`
	ChannelID   string `mapstructure:"channel_id"`
	ChannelName string `mapstructure:"channel_name"`
}

// ConfigSetupFunc configures a Viper instance with command-specific flags,
// environment variables, and default values.
type ConfigSetupFunc func(*viper.Viper)

func New(path string, setupFuncs ...ConfigSetupFunc) (*Config, error) {
	appConfig, err := initConfig(path)
	if err != nil {
		return nil, err
	}

	return new(Config{
		cfg:        appConfig,
		setupFuncs: setupFuncs,
	}), nil
}

func (c *Config) SetViperConfig(v *viper.Viper) {
	c.cfg = v
}

func (c *Config) Load() error {
	if len(c.setupFuncs) != 0 {
		for _, f := range c.setupFuncs {
			f(c.cfg)
		}
	}

	err := c.cfg.Unmarshal(c)
	if err != nil {
		return err
	}
	return c.Validate()
}

func (c *Config) Validate() error {
	if c.Notifiers.Email.Enabled {
		e := c.Notifiers.Email
		if e.SendAddress == "" {
			return fmt.Errorf("email notifier enabled but the sender address is empty.")
		}
		if e.RecptAddress == "" {
			return fmt.Errorf("email notifier enabled but receiver address is not given")
		}
		if e.Password == "" {
			return fmt.Errorf("email notifier is enabled but passowrd is empty.")
		}
	}

	if c.Notifiers.Discord.Enabled {
		d := c.Notifiers.Discord
		if d.Token == "" {
			return fmt.Errorf("discord notifier enabled but token is empty.")
		}
		if d.ChannelID == "" && d.ChannelName == "" {
			return fmt.Errorf("discord notifier enabled but neither the channel id nor channel name is given.")
		}
	}

	if c.Notify && !c.anyEnabledNotifiers() {
		return fmt.Errorf("there are no enabled notifiers to send scan results to.")
	}
	return nil
}

func (c *Config) anyEnabledNotifiers() bool {
	return c.Notifiers.Email.Enabled || c.Notifiers.Discord.Enabled
}

// initConfig reads in config file and ENV variables if set.
func initConfig(cfgFile string) (*viper.Viper, error) {
	appConfig := viper.New()

	if cfgFile != "" {
		// Use config file from the flag.
		appConfig.SetConfigFile(cfgFile)
	} else {
		configDir, err := ConfigDir()
		if err != nil {
			return nil, err
		}
		appConfig.SetConfigName("gscn")
		appConfig.AddConfigPath(configDir)
	}

	appConfig.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := appConfig.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// if file not found no need to error.
			return appConfig, nil
		}
		return nil, fmt.Errorf("error reading config file %v: %w", viper.ConfigFileUsed(), err)
	}

	return appConfig, nil
}

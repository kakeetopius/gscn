// Package config is used to manage the application's configuration.
package config

import "github.com/spf13/viper"

func Load(cfgFile string) (*viper.Viper, error) {
	appConfig := viper.New()

	if cfgFile != "" {
		appConfig.SetConfigFile(cfgFile)
	} else {
		configDir, err := ConfigDir()
		if err != nil {
			return nil, err
		}
		appConfig.SetConfigName("gscn")
		appConfig.AddConfigPath(configDir)
	}

	// If a config file is found, read it in.
	err := appConfig.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		// No need to return error if config file not found
		return appConfig, nil
	}

	return appConfig, nil
}

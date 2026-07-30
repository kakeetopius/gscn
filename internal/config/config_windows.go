//go:build windows

package config

import "os"

func ConfigDir() (string, error) {
	return os.UserConfigDir()
}

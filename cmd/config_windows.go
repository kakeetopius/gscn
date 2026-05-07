package cmd

import "os"

// go: build windows

func ConfigDir() (string, error) {
	return os.UserConfigDir()
}

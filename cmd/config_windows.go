//go:build windows

package cmd

import "os"

func ConfigDir() (string, error) {
	return os.UserConfigDir()
}

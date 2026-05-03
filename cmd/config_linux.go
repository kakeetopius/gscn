package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path"
)

// go: build linux

func ConfigDir() (string, error) {
	home := ""
	if os.Geteuid() == 0 {
		// running as root
		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser == "" {
			return "", fmt.Errorf("could not get sudo user variable")
		}
		u, err := user.Lookup(sudoUser)
		if err != nil {
			return "", err
		}
		home = u.HomeDir
		return path.Join(home, ".config"), nil
	} else {
		return os.UserConfigDir()
	}
}

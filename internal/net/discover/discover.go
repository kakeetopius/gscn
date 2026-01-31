// Package discover is used to discover hosts on a network using ARP for IPv4 or ICMPv6 Neigbour Discovery for IPv6.
package discover

import (
	"github.com/kakeetopius/gscn/internal/utils"
	"github.com/pterm/pterm"
)

const (
	DoReverseLookup = 1 << iota
	DoIPv6AddressResolution
)

func RunDiscover(opts map[string]string, flags int) error {
	if len(opts) < 1 {
		pterm.Error.Println("No options given. Run gohunter disc -h for more details.")
	}
	err := runArp(opts, flags)
	if err != nil {
		pterm.Error.Println(utils.GetErrString(err))
	}
	return nil
}

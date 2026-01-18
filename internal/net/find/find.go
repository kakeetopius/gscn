// Package find is used to discover hosts on a network using ARP for IPv4 or ICMP Neigbour Discovery for IPv6.
package find

import (
	"github.com/kakeetopius/gscn/internal/utils"
	"github.com/pterm/pterm"
)

const (
	DoReverseLookup = 1 << iota
	DoIPv6AddressResolution
)

func RunFind(opts map[string]string, flags int) error {
	if len(opts) < 1 {
		pterm.Error.Println("No options given. Run gohunter find -h for more details.")
	}
	err := runArp(opts, flags)
	if err != nil {
		pterm.Error.Println(utils.GetErrString(err))
	}
	return nil
}

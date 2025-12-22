// Package find is used to discover hosts on a network using ARP for IPv4 or ICMP Neigbour Discovery for IPv6.
package find

import (
	"fmt"
)

const (
	DoReverseLookup = 1 << iota
)

func RunFind(opts map[string]string, flags int) error {
	fmt.Println("Discovering Host(s).....")

	if len(opts) < 1 {
		fmt.Println("No options provided")
	}
	err := runArp(opts, flags)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return nil
}

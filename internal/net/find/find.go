//Package find is used to discover hosts on a network using ARP for IPv4 or ICMP Neigbour Discovery for IPv6.
package find

import (
	"fmt"
)

func RunFind(opts map[string]string) error {
	fmt.Println("Discovering Host(s).....")

	err := runArp(opts)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return nil
}

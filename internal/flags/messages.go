package flags

import (
	"fmt"
)

func GeneralUsage() {
	message := 
`Usage: gohunter [COMMAND] [OPTIONS]

Available Commands:
  find					discover hosts on a network.
  scan					Scan hosts on a network.
  wifi					Do various operations on a WiFi network.
  help					Show this help message.

Use gohunter <COMMAND> --help or -h to get more information about a command.
`
	fmt.Println(message)
}

func findUsage() {
	message := 
`Usage of find:  gohunter find [OPTIONS]

gohunter find discovers hosts on the network using ARP for IPv4 network and ICMP Neighbor discovery for IPv6. 

Available Options:
  -H, --host			An IPv4 address of a host to find on the network.
  -n, --network			A network address with subnet mask in CIDR notation eg 10.10.10.1/24.
  -i, --iface			A network interface to scan hosts from. Can be used instead of --network
  -h, --help			Show this help message.
`
	fmt.Println(message)
}

func scanUsage() {
	message := 
`Usage of scan:  gohunter scan [OPTIONS]

gohunter scan determines information about hosts connected on a network for example open ports.

Available Options:
  -H, --host			An IPv4 address of a host to scan on the network.
  -n, --network			A network address with subnet mask in CIDR notation eg 10.10.10.1/24.
  -i, --iface			A network interface to scan hosts from. Can be used instead of --network
  -p, --port			Specifies a particular port to scan.
  -P, --port-range		Specifies a range of ports to scan for example 1-100
  -l, --list			A text file to read host IP addresses from one per line.
  -h, --help			Show this help message.
`
	fmt.Println(message)
}

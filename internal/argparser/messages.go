package argparser

import (
	"fmt"

	_ "github.com/pterm/pterm"
)

func GeneralUsage() {
	message := `Usage: gscn <COMMAND> [OPTIONS]

Commands:
  disc		Discover hosts connected to the local network.
  scan		Scan hosts on any network.
  wifi		Do various operations on a WiFi network.
  help		Show this help message.

Use gscn <COMMAND> --help or -h to get more information about a command.
`
	fmt.Println(message)
}

func discoverUsage() {
	message := `Usage of disc:  gscn disc [OPTIONS]

gscn discover discovers hosts on the local network using ARP for IPv4 network and ICMP Neighbor discovery for IPv6. 

Options:
  -6, --six				Use IPv6's ICMP Neighbor discovery instead of ARP.
  -n, --network				A network address with subnet mask in CIDR notation eg 10.10.10.1/24.
  -H, --host				An IPv4 address of a host to find on the network. Same effect as using a /32(for ipv4) with -n option.
  -i, --iface				A network interface to find neighbouring hosts from. When used the entire subnet the interface is in is scanned.
  -t, --timeout				Amount of time in seconds to wait for ARP responses. Default is 2 seconds.
  -r, --reverse				Carry out a reverse lookup on the IP addresses discovered on the network.
  -h, --help				Show this help message.
`
	fmt.Println(message)
}

func scanUsage() {
	message := `Usage of scan:  gscn scan [OPTIONS]

gscn scan determines information about hosts connected on any network for example open ports.

Options:
  -H, --host			An IPv4 address of a host to scan on the network.
  -n, --network			A network address with subnet mask in CIDR notation eg 10.10.10.1/24.
  -i, --iface			A network interface to scan hosts from.
  -p, --port			Specifies a particular port to scan.
  -P, --port-range		Specifies a range of ports to scan for example 1-100 or 80,443,8080 or 1-100,443,8080
  -l, --list			A text file to read host IP addresses from one per line.
  -h, --help			Show this help message.
`
	fmt.Println(message)
}

package discover

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/bits"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"
)

func runIPv6Disc(opts *DiscoverOptions, cmd *cli.Command) error {
	iface, err := net.InterfaceByName("br-5ddee015f91d")
	if err != nil {
		return err
	}

	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ARP))
	if err != nil {
		return err
	}
	addr := &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: uint16(bits.Htons(unix.ETH_P_ARP)),
	}

	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip := &layers.IPv6{
		SrcIP:      net.ParseIP("fe80::f027:10ff:feed:7b86"),
		DstIP:      net.ParseIP("fe80::b4cc:9aff:fe36:36a1"),
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
	}

	icmp := &layers.ICMPv6{
		TypeCode: layers.ICMPv6TypeNeighborSolicitation << 8,
	}

	nd := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: net.ParseIP("fe80::b4cc:9aff:fe36:36a1"),
		Options: layers.ICMPv6Options{
			layers.ICMPv6Option{
				Type: layers.ICMPv6OptSourceAddress,
				Data: iface.HardwareAddr,
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	icmp.SetNetworkLayerForChecksum(ip)
	err = gopacket.SerializeLayers(buf, options, eth, ip, icmp, nd)
	if err != nil {
		fmt.Println(err)
		return err
	}

	packetBytes := buf.Bytes()

	err = unix.Sendto(sockfd, packetBytes, 0, addr)
	return err
}

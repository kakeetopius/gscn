package discover

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/bits"
	"golang.org/x/sys/unix"
)

func runIPv6Disc(opts *DiscoverOptions) error {
	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ARP))
	if err != nil {
		return err
	}
	addr := &unix.SockaddrLinklayer{
		Ifindex:  opts.Interface.Index,
		Protocol: uint16(bits.Htons(unix.ETH_P_ARP)),
	}

	eth := &layers.Ethernet{
		SrcMAC:       opts.Interface.HardwareAddr,
		DstMAC:       solicitedNodeMacAddress(opts.Target.Addr()),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip := &layers.IPv6{
		SrcIP:      opts.Source.AsSlice(),
		DstIP:      solicitedNodeIPAddress(opts.Target.Addr()),
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}

	icmp := &layers.ICMPv6{
		TypeCode: layers.ICMPv6TypeNeighborSolicitation << 8,
	}

	nd := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: opts.Target.Addr().AsSlice(),
		Options: layers.ICMPv6Options{
			layers.ICMPv6Option{
				Type: layers.ICMPv6OptSourceAddress,
				Data: opts.Interface.HardwareAddr,
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

func solicitedNodeMacAddress(targetIP netip.Addr) net.HardwareAddr {
	// Format is 33:33:33:xx:xx:xx where xx:xx:xx is last 24 bits of the IPv6 Address
	addr := targetIP.As16()
	last24Bits := addr[13:16]

	return net.HardwareAddr{
		0x33, 0x33, 0x33,
		last24Bits[0],
		last24Bits[1],
		last24Bits[2],
	}
}

func solicitedNodeIPAddress(targetIP netip.Addr) net.IP {
	// Format is ff02::1:ffXX:xxxx where xx:xxxx is the last 24 bits of the IPv6 Address
	addr := targetIP.As16()
	last24Bits := addr[13:16]

	solIP := make(net.IP, 16)
	solIP[0] = 0xff
	solIP[1] = 0x02
	solIP[11] = 0x01
	solIP[12] = 0xff

	copy(solIP[13:16], last24Bits)
	return solIP
}

package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/bits"
	"github.com/kakeetopius/gscn/internal/netutils"
	"github.com/pterm/pterm"
	"golang.org/x/sys/unix"
)

func runIPv6Disc(opts *DiscoverOptions) ([]DiscoverResult, error) {
	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ARP))
	if err != nil {
		return nil, err
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
		return nil, err
	}

	packetBytes := buf.Bytes()

	resultChan := make(chan []DiscoverResult)
	startSendChan := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go getNeighbourAdvertisements(ctx, opts.Interface, opts.Target.Addr(), resultChan, startSendChan)

	_, ok := <-startSendChan // wait for packet receving routine to set up
	if !ok {
		return nil, fmt.Errorf("could not capture packets on that interface")
	}
	pterm.Info.Println("Probing host on interface: " + opts.Interface.Name)

	err = unix.Sendto(sockfd, packetBytes, 0, addr)
	if err != nil {
		return nil, err
	}
	packetsSent++
	WaitTimeout(time.Duration(opts.Timeout), "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultChan
	return results, nil
}

func getNeighbourAdvertisements(ctx context.Context, iface *netutils.IfaceOpts, expectedAddr netip.Addr, resultsChan chan<- []DiscoverResult, startSendChan chan<- struct{}) {
	handle, err := pcap.OpenLive(iface.Name, 1600, false, time.Millisecond)
	if err != nil {
		return
	}
	defer handle.Close()
	err = handle.SetBPFFilter("icmp6 and icmp6[0] == 136") // 136 is the number for ICMPv6TypeNeighborSolicitation
	if err != nil {
		fmt.Println("Error setting up packet capturing interface: ", err)
		close(startSendChan)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	results := make([]DiscoverResult, 0)
	startSendChan <- struct{}{}

	for {
		select {
		case <-ctx.Done():
			resultsChan <- results
			return
		case packet, ok := <-packetChan:
			if !ok {
				continue
			}
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); icmpLayer != nil {
				ip6layer := packet.Layer(layers.LayerTypeIPv6)
				ip6packet, ok := ip6layer.(*layers.IPv6)
				if !ok {
					continue
				}
				srcIP := netip.AddrFrom16([16]byte(ip6packet.SrcIP))
				if srcIP != expectedAddr {
					continue
				}
				packetsReceived++
				icmpPacket, _ := icmpLayer.(*layers.ICMPv6NeighborAdvertisement)
				var hwAddr net.HardwareAddr
				for _, icmpOption := range icmpPacket.Options {
					if icmpOption.Type == layers.ICMPv6OptTargetAddress {
						hwAddr = net.HardwareAddr(icmpOption.Data)
						break
					}
				}

				result := DiscoverResult{}
				result.ipAddr = srcIP.String()
				result.macAddr = hwAddr.String()
				if icmpPacket.Router() {
					result.macAddr = fmt.Sprintf("%v (router)", hwAddr)
				}
				results = append(results, result)
			}
		}
	}
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

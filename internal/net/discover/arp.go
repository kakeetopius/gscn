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
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
	"golang.org/x/sys/unix"
)

type socketInfo struct {
	socketFD   int
	socketAddr *unix.SockaddrLinklayer
}

func runArp(opts *DiscoverOptions) ([]DiscoverResult, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ARP))
	if err != nil {
		return nil, err
	}
	addr := &unix.SockaddrLinklayer{
		Ifindex:  opts.Interface.Index,
		Protocol: uint16(bits.Htons(unix.ETH_P_ARP)),
	}
	socketinfo := socketInfo{
		socketFD:   sockfd,
		socketAddr: addr,
	}

	resultsChan := make(chan []DiscoverResult)
	startSending := make(chan struct{})

	go getARPReplies(ctx, opts, resultsChan, startSending)
	_, ok := <-startSending // wait for packet receiving go routine to finish setup.
	if !ok {
		return nil, fmt.Errorf("could not capture packets on the interface")
	}

	pterm.Info.Println("Probing host(s) on interface: " + opts.Interface.Name)
	numHosts := util.HostsInNetworks(opts.Targets)
	bar, err := pterm.DefaultProgressbar.WithTotal(int(numHosts)).Start()
	if err != nil {
		return nil, err
	}

	for _, target := range opts.Targets {
		IPaddr := target.Masked().Addr() // first IP in range
		for target.Contains(IPaddr) {
			if IPaddr == *opts.Source { // skip interfaces' own ip
				bar.Increment()
				IPaddr = IPaddr.Next()
				continue
			} else {
				err = sendArpPacket(opts.Interface, opts.Source, &IPaddr, &socketinfo)
				if err != nil {
					return nil, err
				}
				bar.Increment()
				IPaddr = IPaddr.Next()
			}
		}
	}
	bar.Stop()

	WaitTimeout(time.Duration(opts.Timeout), "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultsChan

	return results, nil
}

func sendArpPacket(iface *util.IfaceOpts, srcIP *netip.Addr, dstIP *netip.Addr, sockinfo *socketInfo) error {
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		Operation:       layers.ARPRequest,
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   6,
		ProtAddressSize: 4,

		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: srcIP.AsSlice(),

		DstHwAddress:   net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress: dstIP.AsSlice(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}

	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		return err
	}

	packetBytes := buf.Bytes()

	err = unix.Sendto(sockinfo.socketFD, packetBytes, 0, sockinfo.socketAddr)
	if err != nil {
		return err
	}
	packetsSent++
	return nil
}

func getARPReplies(ctx context.Context, opts *DiscoverOptions, resultsChan chan<- []DiscoverResult, startSendChan chan<- struct{}) {
	handle, err := pcap.OpenLive(opts.Interface.Name, 1600, false, time.Millisecond)
	if err != nil {
		return
	}
	defer handle.Close()
	err = handle.SetBPFFilter("arp")
	if err != nil {
		fmt.Println("Error setting up packet capturing interface: ", err)
		close(startSendChan)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	results := make([]DiscoverResult, 0, 15)
	receivedFrom := make(map[netip.Addr]struct{}) // to keep track of which IPs we have got replies from

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
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arpPacket, _ := arpLayer.(*layers.ARP)
				if arpPacket.Operation == layers.ARPReply {
					ipAddr, ok := netip.AddrFromSlice(arpPacket.SourceProtAddress)
					if !ok {
						continue
					}
					if !util.CheckIfAddrIsPartOfNetworks(opts.Targets, &ipAddr) {
						// skip responses outside the specified network
						continue
					}
					if ipAddr == *opts.Source {
						// skip responses from the capturing interface to other devices.
						continue
					}
					packetsReceived++
					_, alreadyReceived := receivedFrom[ipAddr]
					if alreadyReceived {
						continue
					}
					receivedFrom[ipAddr] = struct{}{}
					results = append(results, DiscoverResult{
						ipAddr:  ipAddr.String(),
						macAddr: net.HardwareAddr(arpPacket.SourceHwAddress).String(),
					})
				}
			}
		}
	}
}

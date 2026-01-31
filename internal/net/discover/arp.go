package discover

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/utils"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"
)

type socketInfo struct {
	socketFD   int
	socketAddr *unix.SockaddrLinklayer
}

type Results struct {
	ipAddr   string
	macAddr  string
	hostName string
}

var (
	packetsSent     = 0
	packetsReceived = 0
)

func runArp(opts *DiscoverOptions, cmd *cli.Command) error {
	resultSet, err := sendArptoHosts(opts.Target, opts.Interface, time.Duration(opts.Timeout))
	if err != nil {
		return err
	}

	printWithHostNames := false
	if cmd.Bool("reverse") {
		printWithHostNames = true
		getHostNames(resultSet, time.Duration(opts.Timeout))
	}
	displayResults(resultSet, printWithHostNames)
	return nil
}

func sendArptoHosts(network *netip.Prefix, iface *IfaceDetails, responseTimeout time.Duration) ([]Results, error) {
	addHostIP := false
	networkAddress := network.Masked()

	if network.Contains(iface.ifaceIP) {
		addHostIP = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, utils.Htons(unix.ETH_P_ARP))
	if err != nil {
		return nil, err
	}
	addr := &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: uint16(utils.Htons(unix.ETH_P_ARP)),
	}
	socketinfo := socketInfo{
		socketFD:   sockfd,
		socketAddr: addr,
	}

	resultsChan := make(chan []Results)
	startSending := make(chan struct{})

	numHosts := int(math.Pow(2, float64(32-networkAddress.Bits())))

	pterm.Info.Println("Probing host(s) on interface: " + iface.Name)
	bar, err := pterm.DefaultProgressbar.WithTotal(int(numHosts)).Start()
	if err != nil {
		fmt.Println(err)
	}

	go getARPReplies(ctx, iface, &networkAddress, resultsChan, startSending)

	<-startSending // wait for packet receiving go routine to finish setup.
	IPaddr := networkAddress.Addr()
	for network.Contains(IPaddr) {
		if IPaddr == iface.ifaceIP { // skip interfaces' own ip
			bar.Increment()
			IPaddr = IPaddr.Next()
			continue
		} else {
			err = sendArpPacket(iface, &IPaddr, &socketinfo)
			if err != nil {
				fmt.Println(err)
			}
			bar.Increment()
			IPaddr = IPaddr.Next()
		}
	}
	bar.Stop()

	WaitTimeout(responseTimeout, "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultsChan

	if addHostIP {
		results = append(results, Results{
			ipAddr:  iface.ipStrWithoutMask + " (this host)",
			macAddr: iface.macStr,
		})
	}
	return results, nil
}

func sendArpPacket(iface *IfaceDetails, dstIP *netip.Addr, sockinfo *socketInfo) error {
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
		SourceProtAddress: iface.ifaceIP.AsSlice(),

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

func getARPReplies(ctx context.Context, iface *IfaceDetails, expectedPrefix *netip.Prefix, resultsChan chan<- []Results, startSendChan chan<- struct{}) {
	handle, err := pcap.OpenLive(iface.Name, 1600, false, time.Millisecond)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer handle.Close()
	err = handle.SetBPFFilter("arp")
	if err != nil {
		fmt.Println(err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	results := make([]Results, 0, 15)
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
					if !expectedPrefix.Contains(ipAddr) {
						// skip responses outside the specified network
						continue
					}
					if ipAddr == iface.ifaceIP {
						// skip responses from the capturing interface to other devices.
						continue
					}
					packetsReceived++
					_, alreadyReceived := receivedFrom[ipAddr]
					if alreadyReceived {
						continue
					}
					receivedFrom[ipAddr] = struct{}{}
					results = append(results, Results{
						ipAddr:  ipAddr.String(),
						macAddr: net.HardwareAddr(arpPacket.SourceHwAddress).String(),
					})
				}
			}
		}
	}
}

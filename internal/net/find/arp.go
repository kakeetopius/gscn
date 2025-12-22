package find

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gohunter/internal/utils"
	"github.com/pterm/pterm"
)

type socketInfo struct {
	socketFD   int
	socketAddr *syscall.SockaddrLinklayer
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

func runArp(opts map[string]string, flags int) error {
	var iface *net.Interface
	var err error
	var responseTimeout time.Duration
	var ipwithMask string

	hostIPStr, hostfound := opts["host"]
	netStr, netfound := opts["network"]
	ifaceName, ifacefound := opts["iface"]

	if ifacefound {
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return err
		}
	}

	if hostfound {
		ipwithMask = fmt.Sprintf("%v/%v", hostIPStr, 32)
	} else if netfound {
		ipwithMask = netStr
	} else if ifacefound && ipwithMask == "" {
		ipAddr, addrerr := iface.Addrs()
		if addrerr != nil {
			return err
		}
		ipwithMask = ipAddr[0].String()
	} else {
		return fmt.Errorf("no ip(s) or interface to scan given")
	}

	addrWithPrefix, err := netip.ParsePrefix(ipwithMask)
	if err != nil {
		return err
	}

	if !ifacefound {
		addr := addrWithPrefix.Addr()
		// finding an interface to which the given ip or network is connected to
		iface, err = getDevIface(&addr)
		if err != nil {
			return err
		}
	}

	ifaceDetails, err := verifyInterface(iface)
	if err != nil {
		return err
	}

	timeout, found := opts["timeout"]
	if !found {
		responseTimeout = 2
	} else {
		timeout, timeouterr := strconv.Atoi(timeout)
		if timeouterr != nil {
			return timeouterr
		}
		responseTimeout = time.Duration(timeout)
	}

	resultSet, err := sendArptoHosts(&addrWithPrefix, ifaceDetails, responseTimeout)
	if err != nil {
		return err
	}
	printWithHostNames := false
	if flags&DoReverseLookup != 0 {
		printWithHostNames = true
		getHostNames(resultSet)
	}
	displayResults(resultSet, printWithHostNames)
	return nil
}

func sendArptoHosts(prefix *netip.Prefix, iface *IfaceDetails, responseTimeout time.Duration) ([]Results, error) {
	networkAddress := prefix.Masked()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sockfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, utils.Htons(syscall.ETH_P_ARP))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	addr := &syscall.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: uint16(utils.Htons(syscall.ETH_P_ARP)),
	}
	socketinfo := socketInfo{
		socketFD:   sockfd,
		socketAddr: addr,
	}

	resultsChan := make(chan []Results)
	startSending := make(chan struct{})

	numHosts := int(math.Pow(2, float64(32-networkAddress.Bits()))) - 2

	pterm.Info.Println("Sending ARP packets on interface: " + iface.Name)
	bar, err := pterm.DefaultProgressbar.WithTotal(int(numHosts)).Start()
	if err != nil {
		fmt.Println(err)
	}

	go getARPReplies(ctx, iface, &networkAddress, resultsChan, startSending)

	<-startSending // wait for packet receiving go routine to finish setup.

	IPaddr := networkAddress.Addr().Next() // get the first IP in subnet
	addHostIP := false
	for i := 1; i <= numHosts; i++ {
		if IPaddr == iface.ifaceIP {
			addHostIP = true
		} else {
			err = sendArpPacket(iface, &IPaddr, &socketinfo)
		}
		bar.Increment()
		if err != nil {
			fmt.Println(err)
		}
		IPaddr = IPaddr.Next()
	}
	bar.Stop()

	WaitTimeout(responseTimeout, "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultsChan

	if addHostIP {
		results = append(results, Results{
			ipAddr:  iface.ipStrWithoutMask,
			macAddr: iface.macStr,
		})
	}
	return results, nil
}

func sendArpPacket(iface *IfaceDetails, dstIP *netip.Addr, sockinfo *socketInfo) error {
	eth := &layers.Ethernet{
		SrcMAC:       iface.ifaceMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		Operation:       layers.ARPRequest,
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   6,
		ProtAddressSize: 4,

		SourceHwAddress:   iface.ifaceMac,
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

	err = syscall.Sendto(sockinfo.socketFD, packetBytes, 0, sockinfo.socketAddr)
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
	receivedFrom := make(map[netip.Addr]bool) // to keep track of which IPs we have got replies from

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
						continue
					}
					packetsReceived++
					_, alreadyReceived := receivedFrom[ipAddr]
					if alreadyReceived {
						continue
					}
					receivedFrom[ipAddr] = true
					results = append(results, Results{
						ipAddr:  ipAddr.String(),
						macAddr: net.HardwareAddr(arpPacket.SourceHwAddress).String(),
					})
				}
			}
		}
	}
}

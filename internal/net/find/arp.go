package find

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type socketInfo struct {
	socketFD   int
	socketAddr *syscall.SockaddrLinklayer
}

func runArp(opts map[string]string) error {
	var iface *net.Interface
	var err error
	var responseTimeout time.Duration
	var ipwithMask string

	hostIPStr, hostfound := opts["host"]
	if hostfound {
		ipwithMask = fmt.Sprintf("%v/%v", hostIPStr, 32)
	}
	netStr, netfound := opts["network"]
	if netfound {
		ipwithMask = netStr
	}

	prefix, err := netip.ParsePrefix(ipwithMask)
	if err != nil {
		return err
	}

	ifaceName, found := opts["iface"]
	if !found {
		addr := prefix.Addr()
		iface, err = getDevIface(&addr)
		if err != nil {
			return err
		}
	} else {
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return err
		}
	}

	timeout, found := opts["timeout"]
	if !found {
		responseTimeout = 5
	} else {
		timeout, err := strconv.Atoi(timeout)
		if err != nil {
			return err
		}
		responseTimeout = time.Duration(timeout)
	}

	return sendArptoHosts(&prefix, iface, responseTimeout)
}

func sendArptoHosts(prefix *netip.Prefix, iface *net.Interface, responseTimeout time.Duration) error {
	networkPrefix := prefix.Masked()

	ctx, cancelTimeout := context.WithTimeout(context.Background(), responseTimeout*time.Second)
	defer cancelTimeout()

	sockfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(syscall.ETH_P_ARP))
	if err != nil {
		fmt.Println(err)
		return err
	}
	addr := &syscall.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: uint16(htons(syscall.ETH_P_ARP)),
	}
	socketinfo := socketInfo{
		socketFD:   sockfd,
		socketAddr: addr,
	}

	ipMacChan := make(chan map[string]string)
	startSending := make(chan struct{})
	go getARPReplies(ctx, iface, &networkPrefix, ipMacChan, startSending)

	<-startSending //wait for packet receiving go routine to finish setup.
	fmt.Printf("Sending ARP packets on interface: %v\n\n", iface.Name)
	IPaddr := networkPrefix.Addr()
	for networkPrefix.Contains(IPaddr) {
		err = sendArpPacket(iface, &IPaddr, &socketinfo)
		if err != nil {
			fmt.Println(err)
		}
		IPaddr = IPaddr.Next()
	}
	ipMacMap := <-ipMacChan
	for ip, mac := range ipMacMap {
		fmt.Printf("%v:        %v\n", ip, mac)
	}
	return nil
}

func sendArpPacket(iface *net.Interface, dstIP *netip.Addr, sockinfo *socketInfo) error {
	ifaceAddr, err := iface.Addrs()
	if err != nil {
		return err
	}
	ifaceIP, _, err := net.ParseCIDR(ifaceAddr[0].String())
	if err != nil {
		return err
	}

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
		ProtAddressSize: 6,

		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: ifaceIP.To4(),

		DstHwAddress:   net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress: dstIP.AsSlice(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}

	err = gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		return err
	}

	packetBytes := buf.Bytes()

	syscall.Sendto(sockinfo.socketFD, packetBytes, 0, sockinfo.socketAddr)
	return nil
}

func getARPReplies(ctx context.Context, iface *net.Interface, expectedPrefix *netip.Prefix, ipMacchan chan<- map[string]string, startSendChan chan<- struct{}) {
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

	ipMacMap := make(map[string]string, 10)

	startSendChan <- struct{}{}
	for {
		select {
		case <-ctx.Done():
			ipMacchan <- ipMacMap
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
					mac := net.HardwareAddr(arpPacket.SourceHwAddress)
					ipMacMap[ipAddr.String()] = mac.String()
				}
			}
		}
	}
}

func getDevIface(toFind *netip.Addr) (*net.Interface, error) {
	allIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range allIfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			addr, err := netip.ParsePrefix(addr.String())
			if err != nil {
				return nil, err
			}
			// converting the interface to network address and checking if the address(es) to scan are part of that network
			addr = addr.Masked()
			if addr.Contains(*toFind) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no non-loopback interface connected to that network")
}

func htons(num int) int {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(num))
	return int(binary.BigEndian.Uint32(b[:]))
}

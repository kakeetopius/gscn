package resolving

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/packet"
)

type resolver struct {
	resolveCache      map[netip.Addr]netutil.MAC
	cacheMu           sync.RWMutex
	interfaceProvider netutil.NetInterfaceProvider
	macNotFound       map[netip.Addr]struct{}
}

func NewResolver(interfaceProvider netutil.NetInterfaceProvider) *resolver {
	return &resolver{
		resolveCache:      make(map[netip.Addr]netutil.MAC),
		macNotFound:       make(map[netip.Addr]struct{}),
		interfaceProvider: interfaceProvider,
	}
}

func (r *resolver) Resolve(addr netip.Addr) (netutil.MAC, error) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if mac, found := r.resolveCache[addr]; found {
		return mac, nil
	}
	if _, ok := r.macNotFound[addr]; ok {
		return nil, ErrMacNotFound{addr}
	}

	var err error
	var mac netutil.MAC

	if addr.IsLoopback() {
		mac = netutil.MAC{0, 0, 0, 0, 0, 0}
	} else {
		mac, err = r.resolveMAC(addr)
		if err != nil {
			var errMac ErrMacNotFound
			if errors.As(err, &errMac) {
				r.macNotFound[errMac.DstIP] = struct{}{}
			}
			return nil, err
		}
	}

	r.resolveCache[addr] = mac

	return mac, nil
}

func (r *resolver) resolveMAC(addr netip.Addr) (netutil.MAC, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The filter captures all packets sent to `addr`, including any ARP requests generated while resolving the destination MAC. If the kernel does not already
	// have a valid neighbor cache entry for `addr`, the first captured packet may be an ARP request whose Ethernet destination is the broadcast address
	// (ff:ff:ff:ff:ff:ff). In that case, the packet reciever will capture that ARP request packet instead,
	//
	// To avoid this, scanners should first probe eg, ping each target so the kernel resolves and caches its MAC address. Subsequent packets can then be
	// transmitted directly to the destination host, allowing the correct destination MAC to be observed.
	filter := fmt.Sprintf("dst host %s", addr.String())

	allIfaces, err := r.interfaceProvider.Interfaces()
	if err != nil {
		return nil, err
	}
	packetReceiver, err := packet.NewPacketReceiver(ctx, filter, 5, allIfaces...)
	if err != nil {
		return nil, err
	}
	packets := packetReceiver.Packets()
	defer packetReceiver.Close()

	// dial and try to send some data to the destination ip so we can read the dst mac that will be used by the kernel.
	conn, err := net.Dial("udp", net.JoinHostPort(addr.String(), "69"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.Write([]byte("wagwan"))

	var packet gopacket.Packet
	select {
	case <-time.After(500 * time.Millisecond):
		return nil, ErrMacNotFound{DstIP: addr}
	case p, ok := <-packets:
		if !ok {
			return nil, ErrMacNotFound{DstIP: addr}
		}
		packet = p
	}

	eth := packet.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return nil, ErrMacNotFound{DstIP: addr}
	}
	ethHdr, ok := eth.(*layers.Ethernet)
	if !ok {
		return nil, ErrMacNotFound{DstIP: addr}
	}

	// filter out non ip responses
	if ethHdr.EthernetType != layers.EthernetTypeIPv4 && ethHdr.EthernetType != layers.EthernetTypeIPv6 {
		return nil, ErrMacNotFound{DstIP: addr}
	}

	return netutil.MAC(ethHdr.DstMAC), nil
}

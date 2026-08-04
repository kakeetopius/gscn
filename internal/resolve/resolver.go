package resolve

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/packet"
)

type resolver struct {
	resolveCache      map[netip.Addr]netutil.MAC
	cacheMu           sync.RWMutex
	interfaceProvider netutil.NetInterfaceProvider
}

func NewResolver() Resolver {
	return &resolver{
		resolveCache:      make(map[netip.Addr]netutil.MAC),
		interfaceProvider: &netutil.RealNetInterfaceProvider{},
	}
}

func (r *resolver) Resolve(addr netip.Addr) (netutil.MAC, error) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if mac, found := r.resolveCache[addr]; found {
		return mac, nil
	}

	var err error
	var mac netutil.MAC

	if addr.IsLoopback() {
		mac = netutil.MAC{0, 0, 0, 0, 0, 0}
	} else {
		mac, err = r.resolveMAC(addr)
		if err != nil {
			return nil, err
		}
	}

	r.resolveCache[addr] = mac
	return mac, nil
}

func (r *resolver) resolveMAC(addr netip.Addr) (netutil.MAC, error) {
	allIfaces, err := r.interfaceProvider.Interfaces()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	filter := fmt.Sprintf("dst host %s", addr.String())

	packetReceiver, err := packet.NewPacketReceiver(ctx, filter, 1, allIfaces...)
	if err != nil {
		return nil, err
	}
	defer packetReceiver.Close()

	packets := packetReceiver.Packets()

	// dial and try to send some data to the destination ip so we can read the dst mac that will be used by the kernel.
	conn, err := net.Dial("udp", fmt.Sprintf("%v:%v", addr.String(), 69))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.Write([]byte("wagwan"))

	var packet gopacket.Packet
	select {
	case <-time.After(1 * time.Second):
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

	return netutil.MAC(ethHdr.DstMAC), nil
}

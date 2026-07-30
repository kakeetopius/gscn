//go:build !linux

package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/netutil"
)

type PcapPacketSender struct {
	handles     map[int]*pcap.Handle
	mu          *sync.RWMutex
	sendChannel chan packet
	ctx         context.Context
}

type packet struct {
	data          []byte
	outgoingIface *pcap.Handle
}

func NewPacketSender(ctx context.Context) (PacketSender, error) {
	return NewPcapPacketSender(ctx), nil
}

func NewPcapPacketSender(ctx context.Context) *PcapPacketSender {
	ps := &PcapPacketSender{
		handles:     make(map[int]*pcap.Handle),
		sendChannel: make(chan packet, 1500),
		mu:          &sync.RWMutex{},
		ctx:         ctx,
	}

	go ps.startSender()

	return ps
}

func (ps *PcapPacketSender) SendPacket(packetData []byte, iface *netutil.Interface) error {
	if ps.handles == nil {
		ps.handles = make(map[int]*pcap.Handle)
	}

	ps.mu.RLock()
	handle, ok := ps.handles[iface.Index]
	ps.mu.RUnlock()

	if !ok {
		var err error
		handle, err = getIfaceHandle(iface)
		if err != nil {
			return err
		}
		ps.mu.Lock()
		ps.handles[iface.Index] = handle
		ps.mu.Unlock()
	}

	ps.sendChannel <- packet{
		data:          packetData,
		outgoingIface: handle,
	}
	return nil
}

func (ps *PcapPacketSender) startSender() {
	for {
		select {
		case <-ps.ctx.Done():
			return
		case packet, ok := <-ps.sendChannel:
			if !ok {
				return
			}
			packet.outgoingIface.WritePacketData(packet.data)
		}
	}
}

func (ps *PcapPacketSender) Close() error {
	for _, handle := range ps.handles {
		handle.Close()
	}
	close(ps.sendChannel)
	return nil
}

func getIfaceHandle(iface *netutil.Interface) (*pcap.Handle, error) {
	return pcap.OpenLive(iface.PcapName, 1600, false, time.Millisecond)
}

//go:build !linux

package scanner

import (
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/netutil"
)

type PcapPacketSender struct {
	handles map[int]*pcap.Handle
}

func NewPacketSender() (PacketSender, error) {
	return NewPcapPacketSender(), nil
}

func NewPcapPacketSender() PacketSender {
	return &PcapPacketSender{
		handles: make(map[int]*pcap.Handle),
	}
}

func (ps *PcapPacketSender) SendPacket(packet []byte, iface *netutil.Interface) error {
	if ps.handles == nil {
		ps.handles = make(map[int]*pcap.Handle)
	}

	handle, ok := ps.handles[iface.Index]
	if !ok {
		var err error
		handle, err = getIfaceHandle(iface)
		if err != nil {
			return err
		}
		ps.handles[iface.Index] = handle
	}
	return handle.WritePacketData(packet)
}

func (ps *PcapPacketSender) Close() {
	for _, handle := range ps.handles {
		handle.Close()
	}
}

func getIfaceHandle(iface *netutil.Interface) (*pcap.Handle, error) {
	return pcap.OpenLive(iface.PcapName, 1600, false, time.Millisecond)
}

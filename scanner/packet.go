package scanner

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/netutil"
)

type PacketSender interface {
	SendPacket(packet []byte, iface *netutil.Interface) error

	Close()
}

type PacketReceiver interface {
	Packets() chan gopacket.Packet

	AddReceivingInterface(netutil.Interface) error

	Close()
}

type PcapPacketReceiver struct {
	ctx                context.Context
	filter             string
	ifaces             map[int]receivingInterface
	packetChan         chan gopacket.Packet
	channelCapacity    int
	isAlreadyReceiving bool
}

type receivingInterface struct {
	netutil.Interface
	handle *pcap.Handle
}

func NewPacketReceiver(ctx context.Context, filter string, channelCapacity int, receivingInterfaces ...netutil.Interface) (PacketReceiver, error) {
	packetReceiver := PcapPacketReceiver{
		ctx:        ctx,
		filter:     filter,
		ifaces:     make(map[int]receivingInterface),
		packetChan: make(chan gopacket.Packet, channelCapacity),
	}

	for _, iface := range receivingInterfaces {
		packetReceiver.AddReceivingInterface(iface)
	}

	return &packetReceiver, nil
}

func (pr *PcapPacketReceiver) AddReceivingInterface(iface netutil.Interface) error {
	_, found := pr.ifaces[iface.Index]
	if found {
		return nil
	}

	handle, err := pcap.OpenLive(iface.PcapName, 1600, false, time.Millisecond)
	if err != nil {
		return err
	}
	err = handle.SetBPFFilter(pr.filter)
	if err != nil {
		return err
	}

	receivingIface := receivingInterface{
		Interface: iface,
		handle:    handle,
	}
	pr.ifaces[iface.Index] = receivingIface

	if pr.isAlreadyReceiving {
		go capturePacketsOnInterface(pr.ctx, receivingIface, pr.packetChan)
	}

	return nil
}

func (pr *PcapPacketReceiver) Close() {
	for _, iface := range pr.ifaces {
		iface.handle.Close()
	}
}

func (pr *PcapPacketReceiver) Packets() chan gopacket.Packet {
	for _, iface := range pr.ifaces {
		go capturePacketsOnInterface(pr.ctx, iface, pr.packetChan)
	}
	pr.isAlreadyReceiving = true
	return pr.packetChan
}

func capturePacketsOnInterface(ctx context.Context, iface receivingInterface, packetChan chan gopacket.Packet) {
	packetSource := gopacket.NewPacketSource(iface.handle, iface.handle.LinkType())
	ifacePacketChan := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-ifacePacketChan:
			if !ok {
				return
			}
			packetChan <- packet
		}
	}
}

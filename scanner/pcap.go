package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/netutil"
)

type PcapPacketSender struct {
	handles     map[int]*pcap.Handle
	mu          sync.RWMutex
	sendChannel chan packet
	ctx         context.Context
}

type packet struct {
	data          []byte
	outgoingIface *pcap.Handle
}

func NewPcapPacketSender(ctx context.Context) *PcapPacketSender {
	ps := &PcapPacketSender{
		handles:     make(map[int]*pcap.Handle),
		sendChannel: make(chan packet, 1500),
		mu:          sync.RWMutex{},
		ctx:         ctx,
	}

	go ps.startSender()

	return ps
}

func (ps *PcapPacketSender) Type() PacketSenderType {
	return PacketSenderTypePcap
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

	handle, err := getIfaceHandle(&iface)
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

func (pr *PcapPacketReceiver) Close() error {
	for _, iface := range pr.ifaces {
		iface.handle.Close()
	}
	clear(pr.ifaces)
	return nil
}

func (pr *PcapPacketReceiver) Packets() <-chan gopacket.Packet {
	for _, iface := range pr.ifaces {
		go capturePacketsOnInterface(pr.ctx, iface, pr.packetChan)
	}
	pr.isAlreadyReceiving = true
	return pr.packetChan
}

func capturePacketsOnInterface(ctx context.Context, iface receivingInterface, packetChan chan<- gopacket.Packet) {
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

func getIfaceHandle(iface *netutil.Interface) (*pcap.Handle, error) {
	handle, err := pcap.NewInactiveHandle(iface.PcapName)
	if err != nil {
		return nil, err
	}
	err = handle.SetImmediateMode(true)
	if err != nil {
		return nil, err
	}
	err = handle.SetSnapLen(1500)
	if err != nil {
		return nil, err
	}
	err = handle.SetTimeout(time.Millisecond)
	if err != nil {
		return nil, err
	}

	return handle.Activate()
}

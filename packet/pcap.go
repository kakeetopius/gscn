package packet

import (
	"context"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/netutil"
)

type PcapPacketSender struct {
	handles        map[int]*pcap.Handle
	mu             sync.RWMutex
	sendChannel    chan packet
	senderFinished chan struct{}
	ctx            context.Context
	cancelFunc     context.CancelFunc
	closed         bool
}

type packet struct {
	data          []byte
	outgoingIface *pcap.Handle
}

func NewPcapPacketSender(ctx context.Context) *PcapPacketSender {
	newCtx, cancel := context.WithCancel(ctx)
	ps := &PcapPacketSender{
		handles:        make(map[int]*pcap.Handle),
		sendChannel:    make(chan packet, 1500*4),
		senderFinished: make(chan struct{}),
		mu:             sync.RWMutex{},
		ctx:            newCtx,
		cancelFunc:     cancel,
	}

	go ps.startSender()

	return ps
}

func (ps *PcapPacketSender) Type() PacketSenderType {
	return PacketSenderTypePcap
}

func (ps *PcapPacketSender) Wait() {
	close(ps.sendChannel)
	select {
	case <-ps.senderFinished:
	case <-ps.ctx.Done():
	}
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
	defer func() {
		ps.senderFinished <- struct{}{}
	}()

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
	if ps.closed {
		return nil
	}
	ps.closed = true
	for _, handle := range ps.handles {
		handle.Close()
	}
	ps.cancelFunc()
	return nil
}

type PcapPacketReceiver struct {
	ctx        context.Context
	cancelFunc context.CancelFunc
	filter     string
	ifaces     map[int]receivingInterface
	packetChan chan Packet
	receiverWg sync.WaitGroup
	closed     bool
}

type receivingInterface struct {
	netutil.Interface
	handle *pcap.Handle
}

func NewPacketReceiver(ctx context.Context, filter string, channelCapacity int, receivingInterfaces ...netutil.Interface) (*PcapPacketReceiver, error) {
	newCtx, cancel := context.WithCancel(ctx)
	packetReceiver := PcapPacketReceiver{
		ctx:        newCtx,
		cancelFunc: cancel,
		filter:     filter,
		ifaces:     make(map[int]receivingInterface),
		packetChan: make(chan Packet, channelCapacity),
	}

	for _, iface := range receivingInterfaces {
		err := packetReceiver.AddInterface(iface)
		if err != nil {
			return nil, err
		}
	}

	return &packetReceiver, nil
}

func (pr *PcapPacketReceiver) AddInterface(iface netutil.Interface) error {
	_, found := pr.ifaces[iface.Index]
	if found {
		return nil
	}

	handle, err := getIfaceHandle(&iface)
	if err != nil {
		return err
	}

	if pr.filter != "" {
		err = handle.SetBPFFilter(pr.filter)
		if err != nil {
			return err
		}
	}

	receivingIface := receivingInterface{
		Interface: iface,
		handle:    handle,
	}
	pr.ifaces[iface.Index] = receivingIface

	go pr.capturePacketsOnInterface(receivingIface)

	return nil
}

func (pr *PcapPacketReceiver) Close() error {
	if pr.closed {
		return nil
	}

	pr.cancelFunc()
	pr.receiverWg.Wait()

	clear(pr.ifaces)
	close(pr.packetChan)

	pr.closed = true
	return nil
}

func (pr *PcapPacketReceiver) Packets() <-chan Packet {
	return pr.packetChan
}

func (pr *PcapPacketReceiver) capturePacketsOnInterface(iface receivingInterface) {
	pr.receiverWg.Add(1)
	packetSource := gopacket.NewPacketSource(iface.handle, iface.handle.LinkType())
	ifacePacketChan := packetSource.Packets()

	defer func() {
		iface.handle.Close()
		pr.receiverWg.Done()
	}()

	for {
		var packet gopacket.Packet
		var ok bool

		select {
		case <-pr.ctx.Done():
			return
		case packet, ok = <-ifacePacketChan:
			if !ok {
				return
			}
		}

		select {
		case <-pr.ctx.Done():
			return
		case pr.packetChan <- Packet{
			Packet: packet,
			Iface:  iface.Name,
		}:
		}
	}
}

func getIfaceHandle(iface *netutil.Interface) (*pcap.Handle, error) {
	handle, err := pcap.NewInactiveHandle(iface.PcapName)
	if err != nil {
		return nil, err
	}
	defer handle.CleanUp()

	err = handle.SetSnapLen(1500)
	if err != nil {
		return nil, err
	}
	err = handle.SetTimeout(time.Millisecond)
	if err != nil {
		return nil, err
	}
	err = handle.SetImmediateMode(true)
	if err != nil {
		return nil, err
	}
	return handle.Activate()
}

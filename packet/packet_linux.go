//go:build linux

package packet

import (
	"context"
	"fmt"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/bits"
	"github.com/kakeetopius/gscn/internal/netutil"
	packet_raw "github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func GetPacketSender(ctx context.Context, senderType PacketSenderType) (PacketSender, error) {
	switch senderType {
	case PacketSenderTypePcap:
		return NewPcapPacketSender(ctx), nil
	case PacketSenderTypeLinkLayer:
		return NewLinuxPacketSender(ctx)
	case PacketSenderTypeIPLayer:
		return NewLinuxRawIPSender(ctx)
	default:
		return nil, fmt.Errorf("unknown sender type: %v", senderType)
	}
}

func GetPacketReceiver(ctx context.Context, receiverType PacketReceiverType, filter string, channelCapacity int, receivingInterfaces ...netutil.Interface) (PacketReceiver, error) {
	switch receiverType {
	case PacketReceiverTypePcap:
		return NewPcapPacketReceiver(ctx, filter, channelCapacity, receivingInterfaces...)
	case PacketReceiverLinkLayer:
		return NewLinuxPacketReceiver(ctx, filter, channelCapacity, receivingInterfaces...)
	default:
		return nil, fmt.Errorf("unknown or unsupported sender type: %v", receiverType)
	}
}

type LinuxPacketSender struct {
	sendChannel       chan linuxPacket
	socketFD          int
	senderFinished    chan struct{}
	generalSocketAddr unix.SockaddrLinklayer
	ctx               context.Context
	cancelFunc        context.CancelFunc
	closed            bool
}

type linuxPacket struct {
	data          []byte
	outgoingIface unix.SockaddrLinklayer
}

func NewLinuxPacketSender(ctx context.Context) (*LinuxPacketSender, error) {
	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ALL))
	if err != nil {
		return nil, err
	}
	addr := unix.SockaddrLinklayer{
		Protocol: uint16(bits.Htons(unix.ETH_P_ALL)),
	}

	newCtx, cancel := context.WithCancel(ctx)
	ps := &LinuxPacketSender{
		socketFD:          sockfd,
		generalSocketAddr: addr,
		sendChannel:       make(chan linuxPacket, 1500*4),
		senderFinished:    make(chan struct{}),
		ctx:               newCtx,
		cancelFunc:        cancel,
	}

	go ps.startSender()

	return ps, nil
}

func (ps *LinuxPacketSender) Type() PacketSenderType {
	return PacketSenderTypeLinkLayer
}

func (ps *LinuxPacketSender) Wait() {
	close(ps.sendChannel)
	select {
	case <-ps.senderFinished:
	case <-ps.ctx.Done():
	}
}

func (ps *LinuxPacketSender) SendPacket(packetData []byte, iface *netutil.Interface) error {
	addr := ps.generalSocketAddr
	addr.Ifindex = iface.Index

	ps.sendChannel <- linuxPacket{
		data:          packetData,
		outgoingIface: addr,
	}

	return nil
}

func (ps *LinuxPacketSender) Close() error {
	if ps.closed {
		return nil
	}
	ps.closed = true
	ps.cancelFunc()
	return unix.Close(ps.socketFD)
}

func (ps *LinuxPacketSender) startSender() {
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
			err := unix.Sendto(ps.socketFD, packet.data, 0, &packet.outgoingIface)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

type LinuxRawIPSender struct {
	sendChannel    chan linuxIPPacket
	ipv4Sock       int
	ipv6Sock       int
	senderFinished chan struct{}
	ctx            context.Context
	cancelFunc     context.CancelFunc
	closed         bool
}

type linuxIPPacket struct {
	data []byte
}

func NewLinuxRawIPSender(ctx context.Context) (*LinuxRawIPSender, error) {
	ipv4Sock, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}

	ipv6Sock, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}

	//  we'll provide the IP header.
	if err := unix.SetsockoptInt(ipv4Sock, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(ipv4Sock)
		return nil, err
	}

	newCtx, cancel := context.WithCancel(ctx)
	ps := &LinuxRawIPSender{
		ipv4Sock:       ipv4Sock,
		ipv6Sock:       ipv6Sock,
		sendChannel:    make(chan linuxIPPacket, 1500*4),
		senderFinished: make(chan struct{}),
		ctx:            newCtx,
		cancelFunc:     cancel,
	}

	go ps.startSender()

	return ps, nil
}

func (ps *LinuxRawIPSender) Type() PacketSenderType {
	return PacketSenderTypeIPLayer
}

func (ps *LinuxRawIPSender) SendPacket(packetData []byte, _ *netutil.Interface) error {
	ps.sendChannel <- linuxIPPacket{
		data: packetData,
	}

	return nil
}

func (ps *LinuxRawIPSender) Wait() {
	close(ps.sendChannel)
	select {
	case <-ps.senderFinished:
	case <-ps.ctx.Done():
	}
}

func (ps *LinuxRawIPSender) Close() error {
	if ps.closed {
		return nil
	}
	ps.closed = true
	ps.cancelFunc()
	unix.Close(ps.ipv4Sock)
	return unix.Close(ps.ipv6Sock)
}

func (ps *LinuxRawIPSender) startSender() {
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

			if len(packet.data) < 20 {
				continue
			}

			// Assumes packet starts from IP header
			switch packet.data[0] >> 4 { // extract ip version from the raw bytes
			case 4:
				var dst unix.SockaddrInet4
				copy(dst.Addr[:], packet.data[16:20]) // ip4 address is from byte  16 to 19
				_ = unix.Sendto(ps.ipv4Sock, packet.data, 0, &dst)

			case 6:
				var dst unix.SockaddrInet6
				copy(dst.Addr[:], packet.data[24:40]) // ip6 address is from byte 24 to 39
				_ = unix.Sendto(ps.ipv6Sock, packet.data, 0, &dst)

			default:
				continue
			}
		}
	}
}

type LinuxPacketReceiver struct {
	ctx        context.Context
	cancelFunc context.CancelFunc
	filter     string
	ifaces     map[int]linuxreceivingInterface
	packetChan chan Packet
	receiverWg sync.WaitGroup
	closed     bool
}

type linuxreceivingInterface struct {
	netutil.Interface
	conn *packet_raw.Conn
}

func NewLinuxPacketReceiver(ctx context.Context, filter string, channelCapacity int, receivingInterfaces ...netutil.Interface) (*LinuxPacketReceiver, error) {
	newCtx, cancel := context.WithCancel(ctx)
	packetReceiver := LinuxPacketReceiver{
		ctx:        newCtx,
		cancelFunc: cancel,
		filter:     filter,
		ifaces:     make(map[int]linuxreceivingInterface),
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

func (pr *LinuxPacketReceiver) AddInterface(iface netutil.Interface) error {
	_, found := pr.ifaces[iface.Index]
	if found {
		return nil
	}

	conn, err := getIfaceConn(&iface)
	if err != nil {
		return err
	}

	if pr.filter != "" {
		bpfFilter, err := bpfRawInstructions(pr.filter, iface.LinkType)
		if err != nil {
			return err
		}
		err = conn.SetBPF(bpfFilter)
		if err != nil {
			return err
		}
	}

	receivingIface := linuxreceivingInterface{
		Interface: iface,
		conn:      conn,
	}
	pr.ifaces[iface.Index] = receivingIface

	go pr.capturePacketsOnInterface(receivingIface)

	return nil
}

func (pr *LinuxPacketReceiver) Close() error {
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

func (pr *LinuxPacketReceiver) Packets() <-chan Packet {
	return pr.packetChan
}

func (pr *LinuxPacketReceiver) capturePacketsOnInterface(iface linuxreceivingInterface) {
	pr.receiverWg.Add(1)

	defer func() {
		iface.conn.Close()
		pr.receiverWg.Done()
	}()

	ifacePacketChan := make(chan gopacket.Packet, 1024)

	go func() {
		for {
			select {
			case <-pr.ctx.Done():
				return
			default:
			}

			buf := make([]byte, 65535)
			n, _, err := iface.conn.ReadFrom(buf)
			if err != nil {
				continue
			}

			ifacePacketChan <- gopacket.NewPacket(
				buf[:n],
				layers.LayerTypeEthernet,
				gopacket.Default,
			)
		}
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

func getIfaceConn(iface *netutil.Interface) (*packet_raw.Conn, error) {
	return packet_raw.Listen(&iface.Interface, packet_raw.Raw, unix.ETH_P_ALL, nil)
}

func bpfRawInstructions(filter string, ifaceLinktype layers.LinkType) ([]bpf.RawInstruction, error) {
	bpfIns, err := pcap.CompileBPFFilter(ifaceLinktype, 65535, filter)
	if err != nil {
		return nil, err
	}

	rawIns := make([]bpf.RawInstruction, len(bpfIns))

	for i, insn := range bpfIns {
		rawIns[i] = bpf.RawInstruction{
			Op: insn.Code,
			Jt: insn.Jt,
			Jf: insn.Jf,
			K:  insn.K,
		}
	}

	return rawIns, nil
}

//go:build linux

package packet

import (
	"context"
	"fmt"

	"github.com/kakeetopius/gscn/internal/bits"
	"github.com/kakeetopius/gscn/internal/netutil"
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
	<-ps.senderFinished
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
	<-ps.senderFinished
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

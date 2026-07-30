//go:build linux

package scanner

import (
	"context"

	"github.com/kakeetopius/gscn/internal/bits"
	"github.com/kakeetopius/gscn/internal/netutil"
	"golang.org/x/sys/unix"
)

type LinuxPacketSender struct {
	ctx               context.Context
	sendChannel       chan packet
	socketFD          int
	generalSocketAddr *unix.SockaddrLinklayer
}

type packet struct {
	data          []byte
	outgoingIface *unix.SockaddrLinklayer
}

func NewPacketSender(ctx context.Context) (PacketSender, error) {
	return NewLinuxPacketSender(ctx)
}

func NewLinuxPacketSender(ctx context.Context) (*LinuxPacketSender, error) {
	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ALL))
	if err != nil {
		return nil, err
	}
	addr := &unix.SockaddrLinklayer{
		Protocol: uint16(bits.Htons(unix.ETH_P_ALL)),
	}

	ps := &LinuxPacketSender{
		socketFD:          sockfd,
		generalSocketAddr: addr,
		sendChannel:       make(chan packet, 1500),
		ctx:               ctx,
	}

	go ps.startSender()

	return ps, nil
}

func (ps *LinuxPacketSender) SendPacket(packetData []byte, iface *netutil.Interface) error {
	addr := ps.generalSocketAddr
	addr.Ifindex = iface.Index

	ps.sendChannel <- packet{
		data:          packetData,
		outgoingIface: addr,
	}

	return nil
}

func (ps *LinuxPacketSender) Close() error {
	close(ps.sendChannel)
	return nil
}

func (ps *LinuxPacketSender) startSender() {
	for {
		select {
		case <-ps.ctx.Done():
			return
		case packet, ok := <-ps.sendChannel:
			if !ok {
				return
			}
			unix.Sendto(ps.socketFD, packet.data, 0, packet.outgoingIface)
		}
	}
}

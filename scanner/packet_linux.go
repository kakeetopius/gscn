//go:build linux

package scanner

import (
	"fmt"

	"github.com/kakeetopius/gscn/internal/bits"
	"github.com/kakeetopius/gscn/internal/netutil"
	"golang.org/x/sys/unix"
)

type LinuxPacketSender struct {
	socketFD   int
	socketAddr *unix.SockaddrLinklayer
}

func (ps *LinuxPacketSender) SendPacket(packet []byte, iface *netutil.Interface) error {
	if ps == nil {
		return fmt.Errorf("packet sender not initialised")
	}
	ps.socketAddr.Ifindex = iface.Index

	return unix.Sendto(ps.socketFD, packet, 0, ps.socketAddr)
}

func (ps *LinuxPacketSender) Close() {}

func NewPacketSender() (PacketSender, error) {
	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ALL))
	if err != nil {
		return nil, err
	}
	addr := &unix.SockaddrLinklayer{
		Protocol: uint16(bits.Htons(unix.ETH_P_ALL)),
	}

	ps := &LinuxPacketSender{
		socketFD:   sockfd,
		socketAddr: addr,
	}

	return ps, nil
}

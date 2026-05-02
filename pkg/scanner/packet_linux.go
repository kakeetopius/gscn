package scanner

import (
	"net"

	"github.com/kakeetopius/gscn/internal/bits"
	"golang.org/x/sys/unix"
)

// go: build linux

type socketInfo struct {
	socketFD   int
	socketAddr *unix.SockaddrLinklayer
}

var socket *socketInfo

func sendPacket(packet []byte, iface *net.Interface) error {
	if socket == nil {
		err := setUpSocket(iface)
		if err != nil {
			return err
		}
	}
	return unix.Sendto(socket.socketFD, packet, 0, socket.socketAddr)
}

func setUpSocket(iface *net.Interface) error {
	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ARP))
	if err != nil {
		return err
	}
	addr := &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: uint16(bits.Htons(unix.ETH_P_ARP)),
	}

	socket = &socketInfo{
		socketFD:   sockfd,
		socketAddr: addr,
	}

	return nil
}

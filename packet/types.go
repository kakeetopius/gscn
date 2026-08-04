// Package packet implements logic for sending and receiving packets.
package packet

import (
	"io"

	"github.com/google/gopacket"
	"github.com/kakeetopius/gscn/internal/netutil"
)

// PacketSenderType identifies the implementation used to transmit packets.
type PacketSenderType int

const (
	// PacketSenderTypePcap sends packets using libpcap.
	PacketSenderTypePcap PacketSenderType = iota

	// PacketSenderTypeLinkLayer sends packets using Linux AF_PACKET raw sockets.
	PacketSenderTypeLinkLayer

	// PacketSenderTypeIPLayer sends packets using Linux AF_INET/AF_INET6 raw sockets.
	PacketSenderTypeIPLayer
)

type PacketSender interface {
	Type() PacketSenderType

	SendPacket(packet []byte, iface *netutil.Interface) error

	Wait()

	io.Closer
}

type PacketReceiver interface {
	Packets() <-chan gopacket.Packet

	io.Closer
}

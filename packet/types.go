// Package packet implements logic for sending and receiving packets.
package packet

import (
	"io"

	"github.com/gopacket/gopacket"
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

// PacketSender defines the interface for sending packets
type PacketSender interface {
	// Type returns the packet sender type.
	Type() PacketSenderType

	// SendPacket sends a packet through the specified interface.
	SendPacket(packet []byte, iface *netutil.Interface) error

	// Wait blocks until all queued packets have been sent.
	// After it returns, no more packets can be sent.
	Wait()

	io.Closer
}

// PacketReceiver defines the interface for receiving network packets.
type PacketReceiver interface {
	// AddInterface registers a network interface for packet capture.
	AddInterface(netutil.Interface) error

	// Packets returns a read-only channel for receiving captured packets.
	Packets() <-chan Packet

	io.Closer
}

type Packet struct {
	gopacket.Packet
	// Iface is the name of the interface where the packet was received
	Iface string
}

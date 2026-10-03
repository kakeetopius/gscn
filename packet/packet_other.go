//go:build !linux

package packet

import (
	"context"
	"fmt"

	"github.com/kakeetopius/gscn/internal/netutil"
)

func GetPacketSender(ctx context.Context, senderType PacketSenderType) (PacketSender, error) {
	// other operating systems apart from linux support only the Pcap packet sender
	switch senderType {
	case PacketSenderTypePcap:
		return NewPcapPacketSender(ctx), nil
	default:
		return nil, fmt.Errorf("unknown or unsupported sender type: %v", senderType)
	}
}

func GetPacketReceiver(ctx context.Context, receiverType PacketReceiverType, filter string, channelCapacity int, receivingInterfaces ...netutil.Interface) (PacketReceiver, error) {
	// other operating systems apart from linux support only the Pcap packet receiver
	switch receiverType {
	case PacketReceiverTypePcap:
		return NewPcapPacketReceiver(ctx, filter, channelCapacity, receivingInterfaces...)
	default:
		return nil, fmt.Errorf("unknown or unsupported sender type: %v", receiverType)
	}
}

//go:build !linux

package packet

import (
	"context"
	"fmt"
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

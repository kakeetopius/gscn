package scanner

import (
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

// go: build windows

type socketInfo struct {
	*pcap.Handle
}

var socket *socketInfo

func sendPacket(packet []byte, iface *net.Interface) error {
	if socket == nil {
		err := setUpSocket(iface)
		if err != nil {
			return err
		}
	}
	return socket.WritePacketData(packet)
}

func setUpSocket(iface *net.Interface) error {
	handle, err := pcap.OpenLive(iface.Name, 1600, false, time.Millisecond)
	if err != nil {
		return err
	}
	socket = &socketInfo{
		handle,
	}

	return nil
}

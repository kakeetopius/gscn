package scanner

import (
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/util"
)

// go: build windows

type socketInfo struct {
	*pcap.Handle
}

var socket *socketInfo

func sendPacket(packet []byte, iface *util.Interface) error {
	if socket == nil {
		err := setUpSocket(iface)
		if err != nil {
			return err
		}
	}
	return socket.WritePacketData(packet)
}

func setUpSocket(iface *util.Interface) error {
	handle, err := pcap.OpenLive(iface.PcapName, 1600, false, time.Millisecond)
	if err != nil {
		return err
	}
	socket = &socketInfo{
		handle,
	}

	return nil
}

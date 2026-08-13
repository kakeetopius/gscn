package netutil

import (
	"encoding/json"
	"net"
	"slices"
)

type MAC net.HardwareAddr

func (m MAC) String() string {
	return net.HardwareAddr(m).String()
}

func (m MAC) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.HardwareAddr(m).String())
}

func (m MAC) IsZero() bool {
	return slices.Equal(m, MAC{0, 0, 0, 0, 0, 0})
}

func (m MAC) IsBroadCast() bool {
	return slices.Equal(m, MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
}

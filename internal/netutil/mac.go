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
	zeroMac := MAC{0, 0, 0, 0, 0, 0}

	return slices.Equal(m, zeroMac)
}

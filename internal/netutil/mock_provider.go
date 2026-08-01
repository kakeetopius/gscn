package netutil

import (
	"fmt"
	"net"
	"net/netip"
)

func MockInterfaceProvider() *MockNetInterfaceProvider {
	return new(MockNetInterfaceProvider)
}

var mockInterfaces = []Interface{
	{
		PcapName: "eth0",
		Interface: net.Interface{
			Index:        1,
			MTU:          1500,
			Name:         "eth0",
			HardwareAddr: net.HardwareAddr{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E},
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("192.168.1.10/24"),
			netip.MustParsePrefix("fe80::1a:2b3c:4d5e/64"),
		},
	},
	// Linux ethernet, down, no addresses
	{
		PcapName: "eth1",
		Interface: net.Interface{
			Index:        2,
			MTU:          1500,
			Name:         "eth1",
			HardwareAddr: net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			Flags:        0,
		},
		addresses: []netip.Prefix{},
	},
	// Linux loopback
	{
		PcapName: "lo",
		Interface: net.Interface{
			Index:        3,
			MTU:          65536,
			Name:         "lo",
			HardwareAddr: nil,
			Flags:        net.FlagUp | net.FlagLoopback,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/8"),
			netip.MustParsePrefix("::1/128"),
		},
	},
	// Linux wireless, up, IPv4 only
	{
		PcapName: "wlan0",
		Interface: net.Interface{
			Index:        4,
			MTU:          1500,
			Name:         "wlan0",
			HardwareAddr: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("172.16.0.100/12"),
		},
	},
	// Linux docker bridge, up, IPv4 only
	{
		PcapName: "docker0",
		Interface: net.Interface{
			Index:        5,
			MTU:          1500,
			Name:         "docker0",
			HardwareAddr: net.HardwareAddr{0x02, 0x42, 0xAB, 0xCD, 0xEF, 0x01},
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("172.90.0.1/16"),
		},
	},
	// Linux veth
	{
		PcapName: "veth3a2f1b",
		Interface: net.Interface{
			Index:        6,
			MTU:          1500,
			Name:         "veth3a2f1b",
			HardwareAddr: net.HardwareAddr{0x06, 0x11, 0x22, 0x33, 0x44, 0x55},
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("fe80::411:22ff:fe33:4455/64"),
			netip.MustParsePrefix("2001:db8:1::2/48"),
		},
	},
	// Windows Ethernet adapter
	{
		PcapName: `\Device\NPF_{4B5E6F70-8192-4A3B-BCD0-1E2F3A4B5C6D}`,
		Interface: net.Interface{
			Index:        9,
			MTU:          1500,
			Name:         "Ethernet",
			HardwareAddr: net.HardwareAddr{0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF},
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.105/24"),
			netip.MustParsePrefix("fe80::c:29ff:feab:cdef/64"),
			netip.MustParsePrefix("2001:db8:cafe::105/64"),
		},
	},
	// Windows Wi-Fi adapter
	{
		PcapName: `\Device\NPF_{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}`,
		Interface: net.Interface{
			Index:        10,
			MTU:          1500,
			Name:         "Wi-Fi",
			HardwareAddr: net.HardwareAddr{0x74, 0xD4, 0x35, 0x11, 0x22, 0x33},
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("10.10.1.45/22"),
			netip.MustParsePrefix("fe80::c:29bc:fed8:2/64"),
		},
	},
	// Windows loopback adapter
	{
		PcapName: `\Device\NPF_Loopback`,
		Interface: net.Interface{
			Index:        11,
			MTU:          1500,
			Name:         "Loopback Pseudo-Interface 1",
			HardwareAddr: nil,
			Flags:        net.FlagUp | net.FlagLoopback,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/8"),
			netip.MustParsePrefix("::1/128"),
		},
	},
	{
		PcapName: `\Device\NPF_{DEADBEEF-0000-0000-0000-000000000000}`,
		Interface: net.Interface{
			Index:        13,
			MTU:          1500,
			Name:         "Ethernet 2",
			HardwareAddr: net.HardwareAddr{0x00, 0x50, 0x56, 0xC0, 0x00, 0x08},
			Flags:        0,
		},
		addresses: []netip.Prefix{},
	},
	// Linux dummy
	{
		PcapName: "dummy0",
		Interface: net.Interface{
			Index:        15,
			MTU:          1500,
			Name:         "dummy0",
			HardwareAddr: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Flags:        net.FlagUp | net.FlagBroadcast,
		},
		addresses: []netip.Prefix{
			netip.MustParsePrefix("198.51.100.1/24"),
			netip.MustParsePrefix("198.51.100.2/24"),
			netip.MustParsePrefix("198.51.100.3/24"),
		},
	},
}

type MockNetInterfaceProvider struct{}

func (m *MockNetInterfaceProvider) Interfaces() ([]Interface, error) {
	return mockInterfaces, nil
}

func (m *MockNetInterfaceProvider) AddrsOf(iface *Interface) []netip.Prefix {
	return iface.addresses
}

func (m *MockNetInterfaceProvider) InterfaceByName(name string) (*Interface, error) {
	for i := range mockInterfaces {
		if mockInterfaces[i].Name == name {
			return &mockInterfaces[i], nil
		}
	}
	return nil, fmt.Errorf("interface %q not found", name)
}

func (m *MockNetInterfaceProvider) InterfaceByIndex(index int) (*Interface, error) {
	for i := range mockInterfaces {
		if mockInterfaces[i].Index == index {
			return &mockInterfaces[i], nil
		}
	}
	return nil, fmt.Errorf("interface with index %q not found", index)
}

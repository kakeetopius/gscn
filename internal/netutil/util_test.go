package netutil

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"
)

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
		address: []netip.Prefix{
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
		address: []netip.Prefix{},
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
		address: []netip.Prefix{
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
		address: []netip.Prefix{
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
		address: []netip.Prefix{
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
		address: []netip.Prefix{
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
		address: []netip.Prefix{
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
		address: []netip.Prefix{
			netip.MustParsePrefix("10.10.1.45/22"),
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
		address: []netip.Prefix{
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
		address: []netip.Prefix{},
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
		address: []netip.Prefix{
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
	return iface.address
}

func (m *MockNetInterfaceProvider) InterfaceByName(name string) (*Interface, error) {
	for i := range mockInterfaces {
		if mockInterfaces[i].Name == name {
			return &mockInterfaces[i], nil
		}
	}
	return nil, fmt.Errorf("interface %q not found", name)
}

// --- helpers ---
func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

// ifaceByName pulls an interface out of the mock slice
func ifaceByName(t *testing.T, name string) *Interface {
	t.Helper()
	p := &MockNetInterfaceProvider{}
	iface, err := p.InterfaceByName(name)
	if err != nil {
		t.Fatalf("ifaceByName(%q): %v", name, err)
	}
	return iface
}

func TestGetIfaceByIP(t *testing.T) {
	provider := &MockNetInterfaceProvider{}

	tests := []struct {
		name      string
		ip        netip.Addr
		wantName  string
		wantErr   bool
		errTarget error
	}{
		{
			name:     "ip inside eth0 subnet",
			ip:       mustAddr("192.168.1.50"),
			wantName: "eth0",
		},
		{
			name:     "exact ip of eth0",
			ip:       mustAddr("192.168.1.10"),
			wantName: "eth0",
		},
		{
			name:     "ip inside wlan0 subnet",
			ip:       mustAddr("172.16.0.200"),
			wantName: "wlan0",
		},
		{
			name:     "ip inside docker0 subnet",
			ip:       mustAddr("172.90.0.99"),
			wantName: "docker0",
		},
		{
			name:     "ip inside dummy0 subnet",
			ip:       mustAddr("198.51.100.2"),
			wantName: "dummy0",
		},
		{
			name:     "loopback address matches lo",
			ip:       mustAddr("127.0.0.1"),
			wantName: "lo",
		},
		{
			name:     "another loopback address in /8",
			ip:       mustAddr("127.0.0.50"),
			wantName: "lo",
		},
		{
			name:     "ip inside windows ethernet subnet",
			ip:       mustAddr("192.168.0.200"),
			wantName: "Ethernet",
		},
		{
			name:     "ip inside windows wifi subnet",
			ip:       mustAddr("10.10.1.100"),
			wantName: "Wi-Fi",
		},

		// --- IPv6
		{
			name:     "ipv6 loopback matches lo",
			ip:       mustAddr("::1"),
			wantName: "lo",
		},
		{
			name:     "link-local ipv6 matches eth0",
			ip:       mustAddr("fe80::1a:2b3c:4d5e"),
			wantName: "eth0",
		},
		{
			name:     "global unicast ipv6 matches windows ethernet",
			ip:       mustAddr("2001:db8:cafe::105"),
			wantName: "Ethernet",
		},
		{
			name:     "global unicast ipv6 matches veth",
			ip:       mustAddr("2001:db8:1::2"),
			wantName: "veth3a2f1b",
		},

		// --- Misses ---
		{
			name:      "ip in no interface's subnet",
			ip:        mustAddr("8.8.8.8"),
			wantErr:   true,
			errTarget: ErrNoInterfaceConnectedToTarget,
		},
		{
			name:      "ip in no interface's subnet ipv6",
			ip:        mustAddr("2001:db8:ffff::1"),
			wantErr:   true,
			errTarget: ErrNoInterfaceConnectedToTarget,
		},
		{
			name:      "interface is down with no addresses eth1",
			ip:        mustAddr("10.0.0.1"),
			wantErr:   true,
			errTarget: ErrNoInterfaceConnectedToTarget,
		},
		{
			name:      "broadcast address not in any prefix",
			ip:        mustAddr("255.255.255.255"),
			wantErr:   true,
			errTarget: ErrNoInterfaceConnectedToTarget,
		},
		{
			name:      "unspecified address",
			ip:        mustAddr("0.0.0.0"),
			wantErr:   true,
			errTarget: ErrNoInterfaceConnectedToTarget,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetIfaceByIP(provider, tt.ip)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (iface: %v)", got)
				}
				if tt.errTarget != nil && !errors.Is(err, tt.errTarget) {
					t.Errorf("error = %v, want errors.Is(%v)", err, tt.errTarget)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Name != tt.wantName {
				t.Errorf("got interface %q, want %q", got.Name, tt.wantName)
			}
		})
	}
}

func TestGetFirstIfaceIPNet(t *testing.T) {
	provider := &MockNetInterfaceProvider{}

	tests := []struct {
		name       string
		ifaceName  string
		ip6        bool
		wantPrefix netip.Prefix
		wantErr    bool
	}{
		// --- IPv4 ---
		{
			name:       "eth0 first ipv4 address",
			ifaceName:  "eth0",
			ip6:        false,
			wantPrefix: mustPrefix("192.168.1.10/24"),
		},
		{
			name:       "wlan0 ipv4",
			ifaceName:  "wlan0",
			ip6:        false,
			wantPrefix: mustPrefix("172.16.0.100/12"),
		},
		{
			name:       "docker0 ipv4",
			ifaceName:  "docker0",
			ip6:        false,
			wantPrefix: mustPrefix("172.90.0.1/16"),
		},
		{
			name:       "lo ipv4",
			ifaceName:  "lo",
			ip6:        false,
			wantPrefix: mustPrefix("127.0.0.1/8"),
		},
		{
			name:       "windows ethernet ipv4",
			ifaceName:  "Ethernet",
			ip6:        false,
			wantPrefix: mustPrefix("192.168.0.105/24"),
		},
		{
			name:       "dummy0 first ipv4",
			ifaceName:  "dummy0",
			ip6:        false,
			wantPrefix: mustPrefix("198.51.100.1/24"),
		},

		// --- IPv6 ---
		{
			name:       "eth0 first ipv6 is link-local",
			ifaceName:  "eth0",
			ip6:        true,
			wantPrefix: mustPrefix("fe80::1a:2b3c:4d5e/64"),
		},
		{
			name:       "lo ipv6",
			ifaceName:  "lo",
			ip6:        true,
			wantPrefix: mustPrefix("::1/128"),
		},
		{
			name:       "veth ipv6 first address",
			ifaceName:  "veth3a2f1b",
			ip6:        true,
			wantPrefix: mustPrefix("fe80::411:22ff:fe33:4455/64"),
		},
		{
			name:       "windows ethernet first ipv6 is link-local",
			ifaceName:  "Ethernet",
			ip6:        true,
			wantPrefix: mustPrefix("fe80::c:29ff:feab:cdef/64"),
		},

		// --- No addresses
		{
			name:      "eth1 has no addresses ipv4",
			ifaceName: "eth1",
			ip6:       false,
			wantErr:   true,
		},
		{
			name:      "eth1 has no addresses ipv6",
			ifaceName: "eth1",
			ip6:       true,
			wantErr:   true,
		},
		{
			name:      "windows ethernet 2 has no addresses",
			ifaceName: "Ethernet 2",
			ip6:       false,
			wantErr:   true,
		},

		// --- Wrong family
		{
			name:      "wlan0 ipv4-only asked for ipv6",
			ifaceName: "wlan0",
			ip6:       true,
			wantErr:   true,
		},
		{
			name:      "docker0 ipv4-only asked for ipv6",
			ifaceName: "docker0",
			ip6:       true,
			wantErr:   true,
		},
		{
			name:      "dummy0 ipv4-only asked for ipv6",
			ifaceName: "dummy0",
			ip6:       true,
			wantErr:   true,
		},
		{
			name:      "windows wifi ipv4-only asked for ipv6",
			ifaceName: "Wi-Fi",
			ip6:       true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := ifaceByName(t, tt.ifaceName)
			got, err := GetFirstIfaceIPNet(provider, iface, tt.ip6)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (prefix: %v)", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("got nil prefix, want non-nil")
			}
			if tt.wantPrefix.IsValid() && *got != tt.wantPrefix {
				t.Errorf("got %v, want %v", *got, tt.wantPrefix)
			}
		})
	}
}

func TestGetSourceIPFromInterface(t *testing.T) {
	provider := &MockNetInterfaceProvider{}

	tests := []struct {
		name      string
		ifaceName string
		targets   []netip.Prefix
		ip6       bool
		wantAddr  netip.Addr
		wantErr   bool
	}{
		{
			name:      "target in eth0 ipv4 subnet returns eth0 ip",
			ifaceName: "eth0",
			targets:   []netip.Prefix{mustPrefix("192.168.1.0/24")},
			ip6:       false,
			wantAddr:  mustAddr("192.168.1.10"),
		},
		{
			name:      "target in docker0 subnet returns docker0 ip",
			ifaceName: "docker0",
			targets:   []netip.Prefix{mustPrefix("172.90.0.0/16")},
			ip6:       false,
			wantAddr:  mustAddr("172.90.0.1"),
		},
		{
			name:      "target in lo ipv4 subnet returns loopback",
			ifaceName: "lo",
			targets:   []netip.Prefix{mustPrefix("127.0.0.0/8")},
			ip6:       false,
			wantAddr:  mustAddr("127.0.0.1"),
		},
		{
			name:      "target in eth0 ipv6 subnet returns link-local",
			ifaceName: "eth0",
			targets:   []netip.Prefix{mustPrefix("fe80::/10")},
			ip6:       true,
			wantAddr:  mustAddr("fe80::1a:2b3c:4d5e"),
		},
		{
			name:      "target in lo ipv6 subnet returns ::1",
			ifaceName: "lo",
			targets:   []netip.Prefix{mustPrefix("::1/128")},
			ip6:       true,
			wantAddr:  mustAddr("::1"),
		},
		{
			name:      "target in veth ipv6 global subnet",
			ifaceName: "veth3a2f1b",
			targets:   []netip.Prefix{mustPrefix("2001:db8:1::/48")},
			ip6:       true,
			wantAddr:  mustAddr("2001:db8:1::2"),
		},
		{
			name:      "target matches one of multiple dummy0 addresses",
			ifaceName: "dummy0",
			targets:   []netip.Prefix{mustPrefix("198.51.100.0/24")},
			ip6:       false,
			wantAddr:  mustAddr("198.51.100.1"),
		},

		// --- Multiple targets: first match wins ---
		{
			name:      "first target matches eth0",
			ifaceName: "eth0",
			targets: []netip.Prefix{
				mustPrefix("192.168.1.0/24"),
				mustPrefix("10.0.0.0/8"),
			},
			ip6:      false,
			wantAddr: mustAddr("192.168.1.10"),
		},
		{
			name:      "second target matches after first misses",
			ifaceName: "eth0",
			targets: []netip.Prefix{
				mustPrefix("10.0.0.0/8"),     // not on eth0
				mustPrefix("192.168.1.0/24"), // is on eth0
			},
			ip6:      false,
			wantAddr: mustAddr("192.168.1.10"),
		},

		// --- Fallback: no target matches, returns first addr of family ---
		{
			name:      "no target match falls back to first ipv4 on eth0",
			ifaceName: "eth0",
			targets:   []netip.Prefix{mustPrefix("10.99.0.0/24")},
			ip6:       false,
			wantAddr:  mustAddr("192.168.1.10"),
		},
		{
			name:      "no target match falls back to first ipv6 on lo",
			ifaceName: "lo",
			targets:   []netip.Prefix{mustPrefix("2001:db8:ffff::/48")},
			ip6:       true,
			wantAddr:  mustAddr("::1"),
		},
		{
			name:      "empty targets falls back to first ipv4",
			ifaceName: "wlan0",
			targets:   []netip.Prefix{},
			ip6:       false,
			wantAddr:  mustAddr("172.16.0.100"),
		},
		{
			name:      "nil targets falls back to first ipv4",
			ifaceName: "docker0",
			targets:   nil,
			ip6:       false,
			wantAddr:  mustAddr("172.90.0.1"),
		},

		// --- Errors: no address of requested family ---
		{
			name:      "wlan0 has no ipv6 address",
			ifaceName: "wlan0",
			targets:   []netip.Prefix{mustPrefix("fe80::/10")},
			ip6:       true,
			wantErr:   true,
		},
		{
			name:      "docker0 has no ipv6 address",
			ifaceName: "docker0",
			targets:   []netip.Prefix{},
			ip6:       true,
			wantErr:   true,
		},
		{
			name:      "eth1 has no addresses at all ipv4",
			ifaceName: "eth1",
			targets:   []netip.Prefix{mustPrefix("10.0.0.0/8")},
			ip6:       false,
			wantErr:   true,
		},
		{
			name:      "eth1 has no addresses at all ipv6",
			ifaceName: "eth1",
			targets:   []netip.Prefix{},
			ip6:       true,
			wantErr:   true,
		},
		{
			name:      "windows ethernet 2 down no addresses ipv4",
			ifaceName: "Ethernet 2",
			targets:   []netip.Prefix{mustPrefix("192.168.0.0/24")},
			ip6:       false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := ifaceByName(t, tt.ifaceName)
			got, err := GetSourceIPFromInterface(provider, iface, tt.targets, tt.ip6)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (addr: %v)", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("got nil addr, want non-nil")
			}

			if !got.IsValid() {
				t.Errorf("got invalid address :%v", got)
			}
			if *got != tt.wantAddr {
				t.Errorf("got %v, want %v", *got, tt.wantAddr)
			}
		})
	}
}

func TestIPNetToPrefix(t *testing.T) {
	tests := []struct {
		name    string
		ipnet   *net.IPNet
		want    netip.Prefix
		wantErr bool
	}{
		{
			name: "ipv4",
			ipnet: &net.IPNet{
				IP:   net.ParseIP("192.168.1.0"),
				Mask: net.CIDRMask(24, 32),
			},
			want: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name: "ipv6",
			ipnet: &net.IPNet{
				IP:   net.ParseIP("2001:db8::"),
				Mask: net.CIDRMask(64, 128),
			},
			want: netip.MustParsePrefix("2001:db8::/64"),
		},
		{
			name: "invalid ip",
			ipnet: &net.IPNet{
				IP:   net.IP{},
				Mask: net.CIDRMask(24, 32),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IPNetToPrefix(tt.ipnet)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

type mockAddr struct{}

func (m mockAddr) Network() string { return "mock" }
func (m mockAddr) String() string  { return "mock" }

func TestAddrSliceToPrefixSlice(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []net.Addr
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name: "single prefix",
			addrs: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "multiple prefixes",
			addrs: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("10.0.0.0"),
					Mask: net.CIDRMask(8, 32),
				},
				&net.IPNet{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "invalid addr type",
			addrs: []net.Addr{
				mockAddr{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddrSliceToPrefixSlice(tt.addrs)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddrIsPartOfNetworks(t *testing.T) {
	tests := []struct {
		name     string
		targets  []netip.Prefix
		addr     netip.Addr
		expected bool
	}{
		{
			name: "contained",
			targets: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			addr:     netip.MustParseAddr("192.168.1.50"),
			expected: true,
		},
		{
			name: "not contained",
			targets: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			addr:     netip.MustParseAddr("10.0.0.1"),
			expected: false,
		},
		{
			name: "multiple networks",
			targets: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/16"),
			},
			addr:     netip.MustParseAddr("172.16.1.1"),
			expected: true,
		},
		{
			name:     "empty targets",
			targets:  nil,
			addr:     netip.MustParseAddr("192.168.1.1"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AddrIsPartOfNetworks(tt.targets, &tt.addr)

			if got != tt.expected {
				t.Fatalf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHostsInIP4Network(t *testing.T) {
	tests := []struct {
		name     string
		targets  []netip.Prefix
		expected int
	}{
		{
			name: "single host",
			targets: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.1/32"),
			},
			expected: 1,
		},
		{
			name: "24 network",
			targets: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			expected: 254,
		},
		{
			name: "30 network",
			targets: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/30"),
			},
			expected: 2,
		},
		{
			name: "multiple networks",
			targets: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/30"), // 2
				netip.MustParsePrefix("10.0.0.1/32"),    // 1
			},
			expected: 3,
		},
		{
			name: "ipv6 network should be ignored",
			targets: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/30"), // 2 hosts
				netip.MustParsePrefix("2001:db8::/64"),
			},
			expected: 2,
		},
		{
			name:     "empty",
			targets:  nil,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HostsInIP4Network(tt.targets)

			if got != tt.expected {
				t.Fatalf("got %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestService(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "http",
			input:    "80(http)",
			expected: "http",
		},
		{
			name:     "https",
			input:    "443(https)",
			expected: "https",
		},
		{
			name:     "number only",
			input:    "53",
			expected: "",
		},
		{
			name:     "missing closing bracket",
			input:    "80(http",
			expected: "",
		},
		{
			name:     "missing opening bracket",
			input:    "80http)",
			expected: "",
		},
		{
			name:     "empty service",
			input:    "80()",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Service(tt.input)

			if got != tt.expected {
				t.Fatalf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

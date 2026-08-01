package netutil

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			name:     "ip for eth0",
			ip:       mustAddr("192.168.1.10"),
			wantName: "eth0",
		},
		{
			name:     "ip on wlan0",
			ip:       mustAddr("172.16.0.100"),
			wantName: "wlan0",
		},
		{
			name:     "ip for docker0",
			ip:       mustAddr("172.90.0.1"),
			wantName: "docker0",
		},
		{
			name:     "one of the ips for dummy0",
			ip:       mustAddr("198.51.100.2"),
			wantName: "dummy0",
		},
		{
			name:     "loopback address matches lo",
			ip:       mustAddr("127.0.0.1"),
			wantName: "lo",
		},
		{
			name:     "ip for windows ethernet",
			ip:       mustAddr("192.168.0.105"),
			wantName: "Ethernet",
		},
		{
			name:     "ip for windows wifi",
			ip:       mustAddr("10.10.1.45"),
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
			name:      "ip that doesn't exist on any interface",
			ip:        mustAddr("8.8.8.8"),
			wantErr:   true,
			errTarget: ErrNoInterfaceConnectedToTarget,
		},
		{
			name:      "ipv6 address that belongs to no interface",
			ip:        mustAddr("2001:db8:ffff::1"),
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
				require.Error(t, err)
				if tt.errTarget != nil && !errors.Is(err, tt.errTarget) {
					t.Errorf("error = %v, want errors.Is(%v)", err, tt.errTarget)
				}
				return
			}

			require.NoError(t, err)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := ifaceByName(t, tt.ifaceName)
			got, err := GetFirstIfaceIPNet(provider, iface, tt.ip6)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
			if tt.wantPrefix.IsValid() && *got != tt.wantPrefix {
				t.Errorf("got %v, want %v", *got, tt.wantPrefix)
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
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

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
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
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

func TestGetIfaceAddrOnSameNetworkAs(t *testing.T) {
	provider := MockInterfaceProvider()

	tests := []struct {
		name      string
		ifaceName string
		target    netip.Addr
		want      netip.Addr
		wantErr   bool
	}{
		{
			name:      "eth0 ipv4",
			ifaceName: "eth0",
			target:    mustAddr("192.168.1.200"),
			want:      mustAddr("192.168.1.10"),
		},
		{
			name:      "eth0 ipv6",
			ifaceName: "eth0",
			target:    mustAddr("fe80::1234"),
			want:      mustAddr("fe80::1a:2b3c:4d5e"),
		},
		{
			name:      "wlan0 ipv4",
			ifaceName: "wlan0",
			target:    mustAddr("172.16.50.1"),
			want:      mustAddr("172.16.0.100"),
		},
		{
			name:      "docker0 ipv4",
			ifaceName: "docker0",
			target:    mustAddr("172.90.25.9"),
			want:      mustAddr("172.90.0.1"),
		},
		{
			name:      "dummy0",
			ifaceName: "dummy0",
			target:    mustAddr("198.51.100.200"),
			want:      mustAddr("198.51.100.1"),
		},
		{
			name:      "windows ethernet ipv4",
			ifaceName: "Ethernet",
			target:    mustAddr("192.168.0.250"),
			want:      mustAddr("192.168.0.105"),
		},
		{
			name:      "windows ethernet ipv6",
			ifaceName: "Ethernet",
			target:    mustAddr("2001:db8:cafe::abcd"),
			want:      mustAddr("2001:db8:cafe::105"),
		},
		{
			name:      "veth global ipv6",
			ifaceName: "veth3a2f1b",
			target:    mustAddr("2001:db8:1::100"),
			want:      mustAddr("2001:db8:1::2"),
		},
		{
			name:      "veth link-local ipv6",
			ifaceName: "veth3a2f1b",
			target:    mustAddr("fe80::abcd"),
			want:      mustAddr("fe80::411:22ff:fe33:4455"),
		},
		{
			name:      "wrong network",
			ifaceName: "eth0",
			target:    mustAddr("10.0.0.1"),
			wantErr:   true,
		},
		{
			name:      "ipv6 requested on ipv4-only interface",
			ifaceName: "wlan0",
			target:    mustAddr("2001:db8::1"),
			wantErr:   true,
		},
		{
			name:      "interface has no addresses",
			ifaceName: "eth1",
			target:    mustAddr("192.168.1.1"),
			wantErr:   true,
		},
		{
			name:      "windows ethernet2 has no addresses",
			ifaceName: "Ethernet 2",
			target:    mustAddr("192.168.0.1"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := ifaceByName(t, tt.ifaceName)

			got, err := GetIfaceAddrOnSameNetworkAs(provider, tt.target, iface)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

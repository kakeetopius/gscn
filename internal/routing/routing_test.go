package routing

import (
	"net/netip"
	"testing"

	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneralRouterLookup(t *testing.T) {
	r := router{
		v4Table:       new(RoutingTable),
		v6Table:       new(RoutingTable),
		ifaceProvider: netutil.MockInterfaceProvider(),
	}

	eth0, _ := netutil.MockInterfaceProvider().InterfaceByName("eth0")
	wlan0, _ := netutil.MockInterfaceProvider().InterfaceByName("wlan0")
	dummy0, _ := netutil.MockInterfaceProvider().InterfaceByName("dummy0")
	Ethernet, _ := netutil.MockInterfaceProvider().InterfaceByName("Ethernet")
	Wifi, _ := netutil.MockInterfaceProvider().InterfaceByName("Wi-Fi")

	routes := Routes{
		// Default route.
		{
			Network:   netip.MustParsePrefix("0.0.0.0/0"),
			NextHop:   netip.MustParseAddr("192.168.1.1"),
			Interface: eth0,
			Metric:    100,
		},

		// Same prefix, different metric.
		{
			Network:   netip.MustParsePrefix("10.0.0.0/8"),
			NextHop:   netip.MustParseAddr("192.168.1.1"),
			Interface: eth0,
			Metric:    100,
		},
		{
			Network:   netip.MustParsePrefix("10.0.0.0/8"),
			NextHop:   netip.MustParseAddr("172.16.0.1"),
			Interface: wlan0,
			Metric:    50,
		},

		// More-specific route should beat the /8 above,
		// regardless of its higher metric.
		{
			Network:   netip.MustParsePrefix("10.1.0.0/16"),
			NextHop:   netip.MustParseAddr("192.168.1.254"),
			Interface: eth0,
			Metric:    200,
		},

		// Directly connected IPv4 network.
		{
			Network:   netip.MustParsePrefix("172.16.0.0/12"),
			NextHop:   netip.IPv4Unspecified(),
			Interface: wlan0,
			Metric:    100,
		},

		// Another directly connected IPv4 network.
		{
			Network:   netip.MustParsePrefix("198.51.100.0/24"),
			NextHop:   netip.IPv4Unspecified(),
			Interface: dummy0,
			Metric:    100,
		},

		// IPv6 global route.
		{
			Network:   netip.MustParsePrefix("2001:db8:cafe::/64"),
			NextHop:   netip.MustParseAddr("2001:db8:cafe::1"),
			Interface: Ethernet,
			Metric:    100,
		},

		// IPv6 directly connected network.
		{
			Network:   netip.MustParsePrefix("2001:db8:abcd::/64"),
			NextHop:   netip.IPv6Unspecified(),
			Interface: Ethernet,
			Metric:    100,
		},

		// IPv6 link-local routes on different interfaces.
		{
			Network:   netip.MustParsePrefix("fe80::/64"),
			NextHop:   netip.IPv6Unspecified(),
			Interface: Ethernet,
			Metric:    100,
		},
		{
			Network:   netip.MustParsePrefix("fe80::/64"),
			NextHop:   netip.IPv6Unspecified(),
			Interface: Wifi,
			Metric:    100,
		},
	}

	for _, route := range routes {
		switch {
		case route.Network.Addr().Is4():
			r.v4Table.insertRoute(route)
		case route.Network.Addr().Is6():
			r.v6Table.insertRoute(route)
		}
	}

	tests := []struct {
		name        string
		dst         netip.Addr
		wantNetwork netip.Prefix
		wantNextHop netip.Addr
		wantIface   string
		wantDirect  bool
		wantErr     bool
	}{
		{
			name:        "no matching route",
			dst:         netip.MustParseAddr("192.0.2.1"),
			wantErr:     false,
			wantNetwork: netip.MustParsePrefix("0.0.0.0/0"),
			wantNextHop: netip.MustParseAddr("192.168.1.1"),
			wantIface:   "eth0",
			wantDirect:  false,
		},
		{
			name:        "default route",
			dst:         netip.MustParseAddr("8.8.8.8"),
			wantNetwork: netip.MustParsePrefix("0.0.0.0/0"),
			wantNextHop: netip.MustParseAddr("192.168.1.1"),
			wantIface:   "eth0",
			wantDirect:  false,
		},
		{
			name:        "lower metric wins for equal prefix length",
			dst:         netip.MustParseAddr("10.20.30.40"),
			wantNetwork: netip.MustParsePrefix("10.0.0.0/8"),
			wantNextHop: netip.MustParseAddr("172.16.0.1"),
			wantIface:   "wlan0",
			wantDirect:  false,
		},
		{
			name:        "longest prefix wins over lower metric",
			dst:         netip.MustParseAddr("10.1.2.3"),
			wantNetwork: netip.MustParsePrefix("10.1.0.0/16"),
			wantNextHop: netip.MustParseAddr("192.168.1.254"),
			wantIface:   "eth0",
			wantDirect:  false,
		},
		{
			name:        "directly connected IPv4",
			dst:         netip.MustParseAddr("172.16.10.20"),
			wantNetwork: netip.MustParsePrefix("172.16.0.0/12"),
			wantNextHop: netip.MustParseAddr("172.16.10.20"),
			wantIface:   "wlan0",
			wantDirect:  true,
		},
		{
			name:        "directly connected IPv4 on dummy interface",
			dst:         netip.MustParseAddr("198.51.100.42"),
			wantNetwork: netip.MustParsePrefix("198.51.100.0/24"),
			wantNextHop: netip.MustParseAddr("198.51.100.42"),
			wantIface:   "dummy0",
			wantDirect:  true,
		},
		{
			name:        "IPv6 next hop",
			dst:         netip.MustParseAddr("2001:db8:cafe::1234"),
			wantNetwork: netip.MustParsePrefix("2001:db8:cafe::/64"),
			wantNextHop: netip.MustParseAddr("2001:db8:cafe::1"),
			wantIface:   "Ethernet",
			wantDirect:  false,
		},
		{
			name:        "directly connected IPv6",
			dst:         netip.MustParseAddr("2001:db8:abcd::1234"),
			wantNetwork: netip.MustParsePrefix("2001:db8:abcd::/64"),
			wantNextHop: netip.MustParseAddr("2001:db8:abcd::1234"),
			wantIface:   "Ethernet",
			wantDirect:  true,
		},
		{
			name:        "IPv6 link-local without zone",
			dst:         netip.MustParseAddr("fe80::1234"),
			wantNetwork: netip.MustParsePrefix("fe80::/64"),
			wantNextHop: netip.MustParseAddr("fe80::1234"),
			wantIface:   "Ethernet",
			wantDirect:  true,
		},
		{
			name:        "IPv6 link-local with zone",
			dst:         netip.MustParseAddr("fe80::1234").WithZone("Wi-Fi"),
			wantNetwork: netip.MustParsePrefix("fe80::/64"),
			wantNextHop: netip.MustParseAddr("fe80::1234").WithZone("Wi-Fi"),
			wantIface:   "Wi-Fi",
			wantDirect:  true,
		},
		{
			name:       "IPv6 link-local with nonexistent zone",
			dst:        netip.MustParseAddr("fe80::1234").WithZone("eth1"),
			wantErr:    true,
			wantDirect: true,
			wantIface:  "eth1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := r.Lookup(tt.dst)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			assert.Equal(t, tt.wantNetwork, route.Network)
			assert.Equal(t, tt.wantNextHop, route.NextHop)
			assert.Equal(t, tt.wantIface, route.Interface.Name)
			assert.Equal(t, tt.wantDirect, route.DirectlyConnected)
		})
	}
}

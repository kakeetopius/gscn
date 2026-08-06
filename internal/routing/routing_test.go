package routing

import (
	"net/netip"
	"testing"

	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneralRouterLookup(t *testing.T) {
	r := generalRouter{
		table: routingTable{
			{
				Network: netip.MustParsePrefix("0.0.0.0/0"),
				Gateway: netip.MustParseAddr("192.168.1.1"),
				IfIndex: 1, // eth0
				Metric:  100,
			},
			{
				Network: netip.MustParsePrefix("172.16.0.0/12"),
				Gateway: netip.IPv4Unspecified(),
				IfIndex: 4, // wlan0
				Metric:  100,
			},
			{
				Network: netip.MustParsePrefix("198.51.100.0/24"),
				Gateway: netip.IPv4Unspecified(),
				IfIndex: 15, // dummy0
				Metric:  50,
			},
			{
				Network: netip.MustParsePrefix("2001:db8:cafe::/64"),
				Gateway: netip.IPv6Unspecified(),
				IfIndex: 9, // Ethernet
				Metric:  100,
			},
			{
				Network: netip.MustParsePrefix("fe80::/64"),
				Gateway: netip.IPv6Unspecified(),
				IfIndex: 9, // Ethernet
				Metric:  100,
			},
			{
				Network: netip.MustParsePrefix("fe80::/64"),
				Gateway: netip.IPv6Unspecified(),
				IfIndex: 10, // Wi-Fi
				Metric:  100,
			},
			{
				Network: netip.MustParsePrefix("fe80::/64"),
				Gateway: netip.IPv6Unspecified(),
				IfIndex: 1, // eth0
				Metric:  100,
			},
			{
				Network: netip.MustParsePrefix("fe80::/64"),
				Gateway: netip.IPv6Unspecified(),
				IfIndex: 6, // veth3a2f1b
				Metric:  100,
			},
			{
				Network: netip.MustParsePrefix("fe80::/64"),
				Gateway: netip.IPv6Unspecified(),
				IfIndex: 9, // Ethernet
				Metric:  100,
			},
		},
		ifaceProvider: netutil.MockInterfaceProvider(),
		cache:         make(map[netip.Addr]Route),
	}

	tests := []struct {
		name        string
		dst         netip.Addr
		wantNetwork netip.Prefix
		wantNextHop netip.Addr
		wantIface   string
		wantSrcAddr netip.Addr
		wantDirect  bool
		wantErr     bool
	}{
		{
			name:        "default route",
			dst:         netip.MustParseAddr("8.8.8.8"),
			wantNetwork: netip.MustParsePrefix("0.0.0.0/0"),
			wantNextHop: netip.MustParseAddr("192.168.1.1"),
			wantIface:   "eth0",
			wantSrcAddr: netip.MustParseAddr("192.168.1.10"),
			wantDirect:  false,
		},
		{
			name:        "directly connected wlan",
			dst:         netip.MustParseAddr("172.16.1.25"),
			wantNextHop: netip.MustParseAddr("172.16.1.25"),
			wantNetwork: netip.MustParsePrefix("172.16.0.0/12"),
			wantIface:   "wlan0",
			wantSrcAddr: netip.MustParseAddr("172.16.0.100"),
			wantDirect:  true,
		},
		{
			name:        "directly connected dummy",
			dst:         netip.MustParseAddr("198.51.100.99"),
			wantNextHop: netip.MustParseAddr("198.51.100.99"),
			wantNetwork: netip.MustParsePrefix("198.51.100.0/24"),
			wantIface:   "dummy0",
			wantSrcAddr: netip.MustParseAddr("198.51.100.1"),
			wantDirect:  true,
		},
		{
			name:        "ipv6 link-local without zone uses first matching route",
			dst:         netip.MustParseAddr("fe80::1234"),
			wantNextHop: netip.MustParseAddr("fe80::1234"),
			wantNetwork: netip.MustParsePrefix("fe80::/64"),
			wantIface:   "Ethernet",
			wantSrcAddr: netip.MustParseAddr("fe80::c:29ff:feab:cdef"),
			wantDirect:  true,
		},
		{
			name:        "ipv6 link-local with zone but no matching route for the interface",
			dst:         netip.MustParseAddr("fe80::1234").WithZone("eth1"),
			wantNextHop: netip.MustParseAddr("fe80::1234"),
			wantNetwork: netip.MustParsePrefix("fe80::/64"),
			wantIface:   "eth1",
			wantSrcAddr: netip.MustParseAddr("fe80::c:29ff:feab:cdef"),
			wantDirect:  true,
			wantErr:     true,
		},
		{
			name:        "ipv6 link-local with zone",
			dst:         netip.MustParseAddr("fe80::1234").WithZone("Wi-Fi"),
			wantNextHop: netip.MustParseAddr("fe80::1234"),
			wantNetwork: netip.MustParsePrefix("fe80::/64"),
			wantIface:   "Wi-Fi",
			wantSrcAddr: netip.MustParseAddr("fe80::c:29bc:fed8:2"),
			wantDirect:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := r.Lookup(tt.dst)
			if tt.wantErr {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantNetwork, route.Network)
			assert.Equal(t, tt.wantIface, route.Interface.Name)
			assert.Equal(t, tt.wantSrcAddr.String(), route.SrcAddr.String())
			assert.Equal(t, tt.wantDirect, route.DirectlyConnected)

			assert.Equal(t, tt.wantNextHop, route.NextHop)
		})
	}
}

//go:build windows

package routing

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/kakeetopius/gscn/internal/netutil"
	"golang.org/x/sys/windows"
)

func getRoutingTable(ifaceProvider netutil.NetInterfaceProvider) (*RoutingTable, error) {
	rTable := new(RoutingTable)
	var table *windows.MibIpForwardTable2
	err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table)
	if err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	rows := table.Rows()
	for _, row := range rows {
		prefix, err := convertToAddr(&row.DestinationPrefix.Prefix)
		if err != nil {
			return nil, err
		}
		prefixLen := row.DestinationPrefix.PrefixLength

		gateway, err := convertToAddr(&row.NextHop)
		if err != nil {
			return nil, err
		}

		iface, err := ifaceProvider.InterfaceByIndex(int(row.InterfaceIndex))
		if err != nil {
			return nil, err
		}

		src, err := iface.AddrOnSameNetworkAs(gateway)
		if err != nil {
			// Fall back to the first interface ip.
			ifAddr, err := iface.FirstAddr(netutil.AddressFamilyOf(gateway))
			if err != nil {
				return nil, err
			}
			src = ifAddr.Addr()
		}

		rTable.insertRoute(Route{
			Network:   netip.PrefixFrom(prefix, int(prefixLen)),
			NextHop:   gateway,
			Metric:    row.Metric,
			Interface: iface,
			SrcAddr:   src,
		})
	}

	return rTable, nil
}

func convertToAddr(sa *windows.RawSockaddrInet) (netip.Addr, error) {
	switch sa.Family {
	case windows.AF_INET:
		sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrFrom4(sa4.Addr), nil

	case windows.AF_INET6:
		sa6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
		return netip.AddrFrom16(sa6.Addr), nil

	default:
		return netip.Addr{}, fmt.Errorf("unknown address family: %d", sa.Family)
	}
}

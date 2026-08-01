//go:build windows

package route

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getRoutingTable() (routingTable, error) {
	rTable := make(routingTable, 0, 5)

	var table *windows.MibIpForwardTable2
	err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table)
	if err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	rows := table.Rows()
	for _, row := range rows {
		routeAddr, err := convertToAddr(&row.DestinationPrefix.Prefix)
		if err != nil {
			return nil, err
		}
		routeAddrLen := row.DestinationPrefix.PrefixLength

		gateway, err := convertToAddr(&row.NextHop)
		if err != nil {
			return nil, err
		}

		routeEntry := routingTableEntry{
			IfIndex: int(row.InterfaceIndex),
			Metric:  row.Metric,
			Network: netip.PrefixFrom(routeAddr, int(routeAddrLen)),
			Gateway: gateway,
		}

		rTable = append(rTable, routeEntry)
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

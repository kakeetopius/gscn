package discover

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/jsimonetti/rtnetlink/rtnl"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/kakeetopius/gscn/pkg/scanner"
)

func NDPResultsUsingNetlink(iface *net.Interface, targets []netip.Prefix) (*scanner.NDPScanResults, error) {
	results := scanner.NDPScanResults{
		ResultSet: make([]scanner.NDPScanResult, 0, 5),
	}
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection to netlink subsystem: %v", err)
	}
	defer conn.Close()

	neighbours, err := conn.Neighbours(iface, syscall.AF_INET6)
	if err != nil {
		return nil, err
	}
	for _, neigh := range neighbours {
		addr, ok := netip.AddrFromSlice(neigh.IP)
		if !ok {
			continue
		}
		if util.AddrIsPartOfNetworks(targets, &addr) {
			results.ResultSet = append(results.ResultSet, scanner.NDPScanResult{
				IPAddr:  neigh.IP.String(),
				MacAddr: neigh.HwAddr.String(),
				Vendor:  util.MACVendor(neigh.HwAddr.String()),
			})
		}
	}
	return &results, nil
}

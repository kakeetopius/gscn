package scanner

import (
	"net/netip"

	"github.com/kakeetopius/gscn/internal/util"
)

// PortScanWorkerResult is the tesult returned by Scanning workers
type PortScanWorkerResult struct {
	HostIP netip.Addr
	Port   Port
}

func sendPortScanningJobs(jobChan chan netip.AddrPort, targets []netip.Prefix, ports []uint) {
	for _, target := range targets {
		for _, port := range ports {
			if util.OnlyIPInRange(target) {
				addrPort := netip.AddrPortFrom(target.Addr(), uint16(port))
				jobChan <- addrPort
				continue
			}
			netAddr := target.Masked()
			addr := netAddr.Addr().Next()
			for netAddr.Contains(addr) {
				// loop over range of IPs
				addrPort := netip.AddrPortFrom(addr, uint16(port))
				jobChan <- addrPort
				addr = addr.Next()
			}
		}
	}
}

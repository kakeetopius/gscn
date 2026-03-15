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

// sendPortScanningJobs generates port scanning jobs for all target addresses and ports,
// sending them to the provided job channel.
//
// For each target prefix and port combination:
//   - If the target is a single IP address, it sends one job (address + port)
//   - If the target is a network range, it iterates through all addresses in the range
//     and sends a job for each address with the given port
//
// The function blocks until all jobs are sent or the channel is closed.
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

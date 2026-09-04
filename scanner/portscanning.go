package scanner

import (
	"cmp"
	"context"
	"net/netip"
	"time"
)

// portScanWorkerResult is the tesult returned by Port Scanning workers
type portScanWorkerResult struct {
	HostIP netip.Addr
	Port   Port
	Banner string
	RTT    time.Duration
}

type portScanJob struct {
	target      netip.AddrPort
	scanTimeout time.Duration
	hostName    string
}

var CommonPorts = []PortNumber{21, 22, 23, 25, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3309, 5432, 5900, 6379, 8080, 8443, 8888}

func sendPortScanningJobs(
	ctx context.Context,
	jobChan chan portScanJob,
	targets []netip.Prefix,
	ports []PortNumber,
	hostNames map[netip.Addr]string,
	scanTimeout time.Duration,
) {
	for _, target := range targets {
		netAddr := target.Masked()

		var addr netip.Addr
		if target.IsSingleIP() {
			addr = netAddr.Addr() // if it is a /32 or /128 for IPv6, then dont skip the network address.
		} else {
			addr = netAddr.Addr().Next() // skip the network address.
		}

		// loop over range of IPs
		for netAddr.Contains(addr) {
			hostName := cmp.Or(hostNames[addr], addr.String())

			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				default:
				}
				addrPort := netip.AddrPortFrom(addr, uint16(port))
				jobChan <- portScanJob{
					target:      addrPort,
					scanTimeout: scanTimeout,
					hostName:    hostName,
				}
			}
			addr = addr.Next()
		}
	}
}

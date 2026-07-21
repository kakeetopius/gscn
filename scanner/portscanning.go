package scanner

import (
	"context"
	"net/netip"
	"time"
)

// PortScanWorkerResult is the tesult returned by Port Scanning workers
type PortScanWorkerResult struct {
	HostIP netip.Addr
	Port   Port
	RTT    time.Duration
}

type PortScanJob struct {
	target      netip.AddrPort
	scanTimeout time.Duration
}

var CommonPorts = []uint{21, 22, 23, 25, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3309, 5432, 5900, 6379, 8080, 8443, 8888}

func sendPortScanningJobs(ctx context.Context, done chan<- struct{}, jobChan chan PortScanJob, targets []netip.Prefix, ports []uint, scanTimeout time.Duration) {
	defer func() {
		done <- struct{}{}
	}()

	for _, target := range targets {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if target.IsSingleIP() {
				addrPort := netip.AddrPortFrom(target.Addr(), uint16(port))
				jobChan <- PortScanJob{
					target:      addrPort,
					scanTimeout: scanTimeout,
				}
				continue
			}
			netAddr := target.Masked()
			addr := netAddr.Addr().Next()
			for netAddr.Contains(addr) {
				// loop over range of IPs
				addrPort := netip.AddrPortFrom(addr, uint16(port))
				jobChan <- PortScanJob{
					target:      addrPort,
					scanTimeout: scanTimeout,
				}
				addr = addr.Next()
			}
		}
	}
}

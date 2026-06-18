package scanner

import (
	"context"
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/util"
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

func sendPortScanningJobs(ctx context.Context, done chan<- struct{}, jobChan chan PortScanJob, targets []netip.Prefix, ports []uint, scanTimeout time.Duration) {
	defer func() {
		close(jobChan)
		done <- struct{}{}
	}()

	for _, target := range targets {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if util.OnlyIPInRange(target) {
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

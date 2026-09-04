package scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

var Probers = map[PortNumber]ServiceProber{
	80:  httpProber,
	22:  sshProber,
	443: httpsProber,
}

type ServiceProber func(net.Conn, portScanJob) (string, error)

func httpProber(conn net.Conn, job portScanJob) (string, error) {
	url := fmt.Sprintf("http://%s", job.hostName)
	return probeHTTP(url)
}

func httpsProber(conn net.Conn, job portScanJob) (string, error) {
	url := fmt.Sprintf("https://%s", job.hostName)
	return probeHTTP(url)
}

func probeHTTP(url string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Head(url)
	if err != nil {
		return "", err
	}

	wantedHeaders := map[string]struct{}{
		"Server":       {},
		"X-Powered-By": {},
	}

	sb := strings.Builder{}
	for k, v := range resp.Header {
		if _, found := wantedHeaders[k]; !found {
			continue
		}
		fmt.Fprintf(&sb, "%s: %s\n", k, strings.Join(v, ","))
	}

	return sb.String(), nil
}

func sshProber(conn net.Conn, job portScanJob) (string, error) {
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)

	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(banner), nil
}

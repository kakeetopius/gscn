package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/mdlayher/wifi"
	"github.com/pterm/pterm"
)

type WiFiScannerOptions struct {
	InterfaceName   string
	AutoInterface   bool
	MessageNotifier notifier.Notifier
}

type WiFiScanResults struct {
	AccessPoints []*wifi.BSS
}

func (r WiFiScanResults) String() string {
	stringBuilder := strings.Builder{}
	fmt.Fprintf(&stringBuilder, "WiFi Scan Results\n\n")
	for _, ap := range r.AccessPoints {
		fmt.Fprintln(&stringBuilder, "SSID: ", ap.SSID)
		fmt.Fprintln(&stringBuilder, "BSSID: ", ap.BSSID)
		fmt.Fprintln(&stringBuilder, "Status: ", ap.Status.String())
		fmt.Fprintln(&stringBuilder, "Freq (MHz): ", ap.Frequency)
		fmt.Fprintln(&stringBuilder, "Channel: ", FreqToChannel(ap.Frequency))
		fmt.Fprintln(&stringBuilder, "Strength (dBm): ", ap.Signal/100)
		fmt.Fprintln(&stringBuilder, "Load: ", ap.Load.String())
		fmt.Fprintln(&stringBuilder)
	}
	return stringBuilder.String()
}

func (WiFiScanResults) ResultType() ScanResultType {
	return WifiScanResultType
}

type WiFiScanStats struct{}

type WiFiScanner struct {
	WiFiScannerOptions
	results WiFiScanResults
	stats   WiFiScanStats
}

func NewWiFiScanner(opts WiFiScannerOptions) *WiFiScanner {
	return &WiFiScanner{
		WiFiScannerOptions: opts,
		results:            WiFiScanResults{},
		stats:              WiFiScanStats{},
	}
}

func (s *WiFiScanner) Scan() error {
	return runWifiScan(s)
}

func (s *WiFiScanner) Results() ScanResults {
	return s.results
}

func (s *WiFiScanner) Stats() ScanStats {
	return s.stats
}

func (s *WiFiScanner) SendResultsViaNotifier() error {
	if s.MessageNotifier == nil {
		return nil
	}
	spinner, err := pterm.DefaultSpinner.Start("Sending Results....")
	if err != nil {
		return err
	}
	defer spinner.Stop()

	return s.MessageNotifier.SendMessage(s.results.String())
}

func runWifiScan(scanner *WiFiScanner) error {
	client, err := wifi.New()
	if err != nil {
		return err
	}
	defer client.Close()

	var iface *wifi.Interface
	if scanner.AutoInterface {
		iface, err = firstWiFiInterface(client)
	} else if scanner.InterfaceName != "" {
		iface, err = wifiInterfaceByName(client, scanner.InterfaceName)
	} else {
		return fmt.Errorf("no wifi interface provided")
	}
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	spinner, err := pterm.DefaultSpinner.Start("Scanning for access points....")
	if err != nil {
		return err
	}
	defer spinner.Stop()
	err = client.Scan(ctx, iface)
	if err != nil {
		return err
	}

	aps, err := client.AccessPoints(iface)
	if err != nil {
		return err
	}

	scanner.results = WiFiScanResults{
		AccessPoints: aps,
	}
	return nil
}

func wifiInterfaceByName(client *wifi.Client, interfaceName string) (*wifi.Interface, error) {
	ifaces, err := client.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Name == interfaceName {
			return iface, nil
		}
	}

	return nil, fmt.Errorf("no wifi interface named '%v' on the system", interfaceName)
}

func firstWiFiInterface(client *wifi.Client) (*wifi.Interface, error) {
	iface, err := client.Interfaces()
	if err != nil {
		return nil, err
	}
	if len(iface) == 0 {
		return nil, fmt.Errorf("the system has no wifi interfaces")
	}

	return iface[0], nil
}

func FreqToChannel(freq int) int {
	// 2.4 GHz band (Reference freq is 2407 with 5Mhz channel spacing)
	if freq >= 2412 && freq <= 2472 {
		return (freq - 2407) / 5
	}
	if freq == 2484 {
		// Special channel doesnt follow formular
		return 14
	}

	// 5 GHz band (Reference freq is 5000)
	if freq >= 5000 && freq <= 5900 {
		return (freq - 5000) / 5
	}

	// 6 GHz band (WiFi 6E- reference freq is 5950)
	if freq >= 5955 && freq <= 7115 {
		return (freq - 5950) / 5
	}

	return 0
}

package scanner

import (
	"context"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/mdlayher/wifi"
	"github.com/pterm/pterm"
)

type WiFiScanner struct {
	WiFiScannerOptions
	results WiFiScanResults
}

type WiFiScannerOptions struct {
	InterfaceName string
	AutoInterface bool
}

type WiFiScanResults struct {
	AccessPoints  []*wifi.BSS `json:"aps"`
	WiFiScanStats `json:"stats"`
}

type WiFiScanStats struct {
	ScanDuration time.Duration `json:"scan_duration"`
}

func NewWiFiScanner(opts WiFiScannerOptions) *WiFiScanner {
	return &WiFiScanner{
		WiFiScannerOptions: opts,
		results:            WiFiScanResults{},
	}
}

func (s *WiFiScanner) Scan(ctx context.Context) (ScanResults, error) {
	start := time.Now()
	err := runWifiScan(ctx, s)
	if err != nil {
		return nil, err
	}
	stop := time.Now()
	s.results.ScanDuration = stop.Sub(start)
	return &s.results, nil
}

func (r *WiFiScanResults) Print() {
	displayWifiScanResults(r)
}

func (r *WiFiScanResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("wifi_scan_results").Parse(WiFiScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func runWifiScan(ctx context.Context, scanner *WiFiScanner) error {
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

func displayWifiScanResults(results *WiFiScanResults) {
	tableData := pterm.TableData{{"SSID", "BSSID", "Status", "Freq (Mhz)", "Channel", "Strength (dBm)", "Stations"}}
	for _, ap := range results.AccessPoints {
		style := pterm.NewStyle(pterm.FgDefault)
		if ap.Status == wifi.BSSStatusAssociated {
			style = pterm.NewStyle(pterm.Bold)
		}
		ssid := style.Sprint(ap.SSID)
		bssid := style.Sprint(ap.BSSID)
		status := style.Sprint(ap.Status)
		freq := style.Sprint(ap.Frequency)
		channel := style.Sprint(FreqToChannel(ap.Frequency))
		signal := style.Sprint(ap.Signal / 100)
		stations := style.Sprint(ap.Load.StationCount)

		tableData = append(tableData, []string{ssid, bssid, status, freq, channel, signal, stations})
	}

	pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-").WithBoxed().WithData(tableData).Render()
}

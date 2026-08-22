package scanner

var ARPScanResultsTemplate = `
ARP Scan Results
================
{{ printf "%-18s %-20s %-30s %s" "IP ADDRESS" "MAC ADDRESS" "HOSTNAME" "VENDOR" }}
{{ printf "%-18s %-20s %-30s %s" "----------" "-----------" "--------" "------" }}
{{- range .HostResults }}
{{ printf "%-18s %-20s %-30s %s" .IPAddr .MacAddr .HostName .Vendor }}
{{- end }}

Stats
-----
Packets Sent:     {{ .PacketsSent }}
Packets Received: {{ .PacketsReceived }}
Scan Duration:    {{ .ScanDuration }}
`

var NDPScanResultsTemplate = `
NDP Scan Results
================
{{ printf "%-40s %-20s %-30s %s" "IP ADDRESS" "MAC ADDRESS" "HOSTNAME" "VENDOR" }}
{{ printf "%-40s %-20s %-30s %s" "----------" "-----------" "--------" "------" }}
{{- range .HostResults }}
{{ printf "%-40s %-20s %-30s %s" .IPAddr .MacAddr .HostName .Vendor }}
{{- end }}

Stats
-----
Packets Sent:     {{ .PacketsSent }}
Packets Received: {{ .PacketsReceived }}
Scan Duration:    {{ .ScanDuration }}
`

var HostResultTemplate = `
Host:      {{ .Addr }}{{ if .HostName }} - {{ .HostName }}{{ end }} ({{ .HostState }})
Open:      {{ .OpenPorts }}
Closed:    {{ .ClosedPorts }}
Filtered:  {{ .FilteredPorts }}
Avg RTT:   {{ .AverageRTT }}
{{ if eq (.HostState.String) "up" }}
{{ printf "%-8s %-12s %-10s %s" "PORT" "PROTOCOL" "STATE" "SERVICE" }}
{{ printf "%-8s %-12s %-10s %s" "----" "--------" "-----" "-------" }}
{{- range .Ports }}
{{ printf "%-8d %-12s %-10s %s" .Number .Protocol .State .Name }}
{{- end }}
{{- end }}
`

var TCPFullScanResultsTemplate = `
TCP Full Scan Results
=====================
{{- range .Results }}
{{ template "host_result" . }}
{{- end }}

Stats
-----
Total Hosts Scanned: {{ .Stats.TotalNumOfHosts }}
Scan Duration:       {{ .Stats.ScanTime }}
`

var TCPSynScanResultsTemplate = `
TCP SYN Scan Results
=====================
{{- range .Results }}
{{ template "host_result" . }}
{{- end }}

Stats
-----
Total Hosts Scanned: {{ .Stats.TotalNumOfHosts }}
Scan Duration:       {{ .Stats.ScanTime }}
`

var UDPScanResultsTemplate = `
UDP Scan Results
================
{{- range .Results }}
{{ template "host_result" . }}
{{- end }}

Stats
-----
Total Hosts Scanned: {{ .Stats.TotalNumOfHosts }}
Scan Duration:       {{ .Stats.ScanTime }}
`

var PingScanResultsTemplate = `
Ping Scan Results
=================
{{ printf "%-40s %-10s %-10s %s" "IP ADDRESS" "HOSTNAME" "STATE" "AVG RTT" }}
{{ printf "%-40s %-30s %-10s %s" "----------" "--------" "-----" "-------" }}
{{- range .HostResults }}
{{ printf "%-40s %-30s %-10s %s" .IP .HostName .HostState .AverageRTT }}
{{- end }}

Stats
-----
Total Hosts Scanned: {{ .TotalHosts }}
Up Hosts:            {{ .UpHosts }}
Down Hosts:          {{ .DownHosts }}
Scan Time:           {{ .ScanTime }}
`

var WiFiScanResultsTemplate = `
WiFi Scan Results
=================
{{ printf "%-32s %-20s %-10s %-10s %-10s %s" "SSID" "BSSID" "FREQ(MHz)" "SIGNAL" "STATUS" "LAST SEEN" }}
{{ printf "%-32s %-20s %-10s %-10s %-10s %s" "----" "-----" "---------" "------" "------" "---------" }}
{{- range .AccessPoints }}
{{ printf "%-32s %-20s %-10d %-10d %-10s %s" .SSID .BSSID .Frequency .Signal .Status .LastSeen }}
{{- end }}

Stats
-----
Scan Duration: {{ .ScanDuration }}
`

var DHCPScanResultsTemplate = `
DHCPv4 Scan Results
===================

{{- range $i, $server := .Servers }}
Server {{ add $i 1 }}
--------
IP Address:     {{ $server.IP }}
MAC Address:    {{ $server.MACAddress }}
Hostname:       {{ $server.HostName }}
Vendor:         {{ $server.Vendor }}

DHCP Options
------------
Offered IP:     {{ $server.OfferedIP }}
Subnet Mask:    {{ $server.SubnetMask }}
Broadcast:      {{ $server.BroadCast }}
Routers:        {{ join $server.Routers }}
DNS Servers:    {{ join $server.DNSServers }}
Domain Name:    {{ $server.DomainName }}
Lease Time:     {{ $server.LeaseTime }}

{{- end }}
Stats
-----
Packets Sent:     {{ .Stats.PacketsSent }}
Packets Received: {{ .Stats.PacketsReceived }}
Scan Duration:    {{ .Stats.ScanDuration }}
`

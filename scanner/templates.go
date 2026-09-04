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
{{ printf "%-40s %-20s %-30s %-10s %s" "IP ADDRESS" "MAC ADDRESS" "IFACE" "HOSTNAME"  "VENDOR" }}
{{ printf "%-40s %-20s %-30s %-10s %s" "----------" "-----------" "--------" "------" "------" }}
{{- range .HostResults }}
{{ printf "%-40s %-20s %-30s %-10s %s" .IPAddr .MacAddr .Iface .HostName .Vendor }}
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
Routers:        {{ joinAddrs $server.Routers }}
DNS Servers:    {{ joinAddrs $server.DNSServers }}
Domain Name:    {{ $server.DomainName }}
Lease Time:     {{ $server.LeaseTime }}

{{- end }}
Stats
-----
Packets Sent:     {{ .Stats.PacketsSent }}
Packets Received: {{ .Stats.PacketsReceived }}
Scan Duration:    {{ .Stats.ScanDuration }}
`

var DHCPv6ScanResultsTemplate = `
DHCPv6 Scan Results
===================

{{- range $i, $server := .Servers }}
Server {{ add $i 1 }}
--------
IP Address:     {{ $server.IP }}
MAC Address:    {{ $server.MACAddress }}
Hostname:       {{ $server.HostName }}
Vendor:         {{ $server.Vendor }}
Interface:      {{ $server.Iface }}

DHCP Options
------------
Offered Address:     {{ $server.IANA.Address }}
Renewal Time:        {{ $server.IANA.RenewalTime }}
Rebind Time:         {{ $server.IANA.RebindTime }}
Preferred Lifetime:  {{ $server.IANA.PreferredLifetime }}
Valid Lifetime:      {{ $server.IANA.ValidLifetime }}
DNS Servers:         {{ joinAddrs $server.DNSRecursiveServers }}
Domain Search List:  {{ join $server.DomainSearchList }}

{{- end }}
Stats
-----
Packets Sent:     {{ .Stats.PacketsSent }}
Packets Received: {{ .Stats.PacketsReceived }}
Scan Duration:    {{ .Stats.ScanDuration }}
`

var NDPRoutersTemplate = `
{{- range $i, $router := .RouterResults }}
Router {{ add $i 1 }}
--------
IP Address:			  {{ $router.IPAddr }}
MAC Address:          {{ $router.MacAddr }}
Hostname:             {{ $router.HostName }}
Vendor:               {{ $router.Vendor }}
Interface:            {{ $router.Iface }}
Managed (M):          {{ $router.Managed }}
Other Config (O):     {{ $router.OtherConfig }}
Advertised Prefixes:  {{ len $router.PrefixInfo }}

{{- range $j, $prefix := $router.PrefixInfo }}
Prefix {{ add $j 1 }}
--------
Prefix:                {{ $prefix.Prefix }}
On-Link (L):           {{ $prefix.OnLink }}
Autonomous (A):        {{ $prefix.SLAACEnabled }}
Valid Lifetime:        {{ $prefix.ValidLifetime }}
Preferred Lifetime:    {{ $prefix.PreferredLifetime }}

{{- end }}
{{- end }}

Stats
-----
Routers Found:     {{ len .RouterResults }}
Packets Sent:      {{ .NDPScanStats.PacketsSent }}
Packets Received:  {{ .NDPScanStats.PacketsReceived }}
Scan Duration:     {{ .NDPScanStats.ScanDuration }}
`

var CDPHostsTemplate = `
{{- range $i, $host := .Hosts }}
Host {{ add $i 1 }}
--------
MAC Address:          {{ $host.MAC }}
CDP Version:          {{ $host.CDPVersion }}
Device ID:            {{ $host.DeviceID }}
Addresses:            {{ joinAddrs $host.Addresses }}
Port ID:              {{ $host.PortID }}
Platform:             {{ $host.Platform }}
Software Version:     {{ $host.SoftwareVersion }}
IP Prefixes:          {{ joinPrefixes $host.IPPrefixes }}
VTP Domain:           {{ $host.VTPDomain }}
Native VLAN:          {{ $host.NativeVLAN }}
Full Duplex:          {{ $host.FullDuplex }}
MTU:                  {{ $host.MTU }}
System Name:          {{ $host.SysName }}
System OID:           {{ $host.SysOID }}
Management IPs:       {{ joinAddrs $host.ManagementIPs }}
Capabilities:         {{ $host.Capabilites }}

{{- end }}

Stats
-----
Hosts Found:          {{ .NumHosts }}
Packets Received:     {{ .PacketsReceived }}
Scan Duration:        {{ .ScanDuration }}
`

package scanner

import (
	"net/netip"
	"testing"
)

func TestTargetsFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantLen int
	}{
		// --- Valid: CIDR ---
		{
			name:    "ipv4 cidr",
			input:   "10.1.1.0/24",
			wantLen: 1,
		},
		{
			name:    "ipv6 cidr",
			input:   "2001:abcd::1/64",
			wantLen: 1,
		},
		{
			name:    "ipv4 host route /32",
			input:   "192.168.1.1/32",
			wantLen: 1,
		},
		{
			name:    "ipv6 host route /128",
			input:   "::1/128",
			wantLen: 1,
		},
		{
			name:    "default route /0",
			input:   "0.0.0.0/0",
			wantLen: 1,
		},

		// --- Valid: single IP ---
		{
			name:    "single ipv4",
			input:   "10.1.1.1",
			wantLen: 1,
		},
		{
			name:    "single ipv6 loopback",
			input:   "::1",
			wantLen: 1,
		},
		{
			name:    "single ipv4 loopback",
			input:   "127.0.0.1",
			wantLen: 1,
		},

		// --- ranges which are valid ---
		{
			name:    "basic ipv4 range",
			input:   "10.1.1.1-2",
			wantLen: 2,
		},
		{
			name:    "single-element range start == end",
			input:   "10.1.1.5-5",
			wantLen: 1,
		},
		{
			name:    "range at octet boundary 254-255",
			input:   "10.1.1.254-255",
			wantLen: 2,
		},

		// --- Valid: comma-separated mixed ---
		{
			name:    "cidr and single ip",
			input:   "10.1.1.0/24,10.2.2.2",
			wantLen: 2,
		},
		{
			name:    "cidr and range",
			input:   "10.1.1.0/24,10.3.3.1-3",
			wantLen: 4,
		},
		{
			name:    "all three types",
			input:   "10.1.1.1/24,10.1.1.1,10.1.1.1-2",
			wantLen: 3,
		},
		{
			name:    "spaces around comma",
			input:   "10.1.1.0/24, 2001:abcd::1/64",
			wantLen: 2,
		},
		{
			name:    "mixed ipv4 and ipv6 cidr",
			input:   "10.1.1.0/24,2001:abcd::1/64",
			wantLen: 2,
		},

		{
			name:    "duplicate cidrs",
			input:   "10.1.1.0/24,10.1.1.0/24",
			wantLen: 1,
		},
		{
			name:    "duplicate single ips",
			input:   "10.1.1.1,10.1.1.1",
			wantLen: 1,
		},
		{
			name:    "three copies deduplicated",
			input:   "10.1.1.1,10.1.1.1,10.1.1.1",
			wantLen: 1,
		},

		// --- Empty / whitespace
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "trailing comma",
			input:   "10.1.1.1,",
			wantErr: true,
		},
		{
			name:    "leading comma",
			input:   ",10.1.1.1",
			wantErr: true,
		},
		{
			name:    "double comma",
			input:   "10.1.1.1,,10.2.2.2",
			wantErr: true,
		},

		// --- Others ---
		{
			name:    "Invalid range",
			input:   "10.1.1.258-260",
			wantErr: true,
		},
		{
			name:    "totally f*ed string",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "ipv4 prefix length too large /33",
			input:   "10.1.1.1/33",
			wantErr: true,
		},
		{
			name:    "ipv6 prefix length too large /129",
			input:   "::1/129",
			wantErr: true,
		},
		{
			name:    "range end non-numeric",
			input:   "10.1.1.1-abc",
			wantErr: true,
		},
		{
			name:    "range end exceeds 255",
			input:   "10.1.1.1-300",
			wantErr: true,
		},
		{
			name:    "one valid one invalid",
			input:   "10.1.1.1,garbage",
			wantErr: true,
		},
		{
			name:    "ip with extra octets",
			input:   "10.1.1.1.1",
			wantErr: true,
		},
		{
			name:    "negative prefix length",
			input:   "10.1.1.1/-1",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TargetsFromString(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (result: %v)", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !allValid(got) {
				t.Errorf("result contains invalid prefixes: %v", got)
			}

			if len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d (result: %v)", len(got), tt.wantLen, got)
			}

			if hasDuplicates(got) {
				t.Errorf("result contains duplicates: %v", got)
			}
		})
	}
}

func TestTargetsFromStringWithDNSLookup(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantErr        bool
		wantLen        int
		wantHosts      int      // minimum entries in the hostname map
		checkHostnames []string // these domain names must appear as values in the hostname map
	}{
		// --- Pure IP inputs (no DNS, hostname map should be empty) ---
		{
			name:      "single ipv4 no dns",
			input:     "10.1.1.1",
			wantLen:   1,
			wantHosts: 0,
		},
		{
			name:      "ipv4 cidr no dns",
			input:     "10.1.1.0/24",
			wantLen:   1,
			wantHosts: 0,
		},
		{
			name:      "ipv4 range no dns",
			input:     "10.1.1.1-3",
			wantLen:   3,
			wantHosts: 0,
		},
		{
			name:      "mixed ip types no dns",
			input:     "10.1.1.0/24,10.2.2.2,10.3.3.1-2",
			wantLen:   4,
			wantHosts: 0,
		},

		// --- Domain name inputs ---
		{
			name:           "single domain",
			input:          "bing.com",
			wantLen:        1,
			wantHosts:      1,
			checkHostnames: []string{"bing.com"},
		},
		{
			name:           "multiple domains",
			input:          "bing.com,google.com",
			wantLen:        2,
			wantHosts:      2,
			checkHostnames: []string{"bing.com", "google.com"},
		},
		{
			name:           "domain resolving to multiple ips",
			input:          "google.com",
			wantLen:        1,
			wantHosts:      1,
			checkHostnames: []string{"google.com"},
		},

		// --- Mixed IP and domain ---
		{
			name:           "cidr and domain",
			input:          "10.1.1.0/24,bing.com",
			wantLen:        2,
			wantHosts:      1,
			checkHostnames: []string{"bing.com"},
		},
		{
			name:           "full mixed example from doc",
			input:          "10.1.1.1/24,10.1.1.1,bing.com,10.1.1.1-2,google.com",
			wantLen:        5,
			wantHosts:      2,
			checkHostnames: []string{"bing.com", "google.com"},
		},
		{
			name:           "single ip and domain",
			input:          "8.8.8.8,google.com",
			wantLen:        2,
			wantHosts:      1,
			checkHostnames: []string{"google.com"},
		},

		// --- Deduplication ---
		{
			name:           "duplicate domain",
			input:          "bing.com,bing.com",
			wantLen:        1,
			wantHosts:      1,
			checkHostnames: []string{"bing.com"},
		},

		// --- Error cases ---
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "non-existent domain errors",
			input:   "this.domain.does.not.exist.invalid",
			wantErr: true,
		},
		{
			name:    "one valid ip one bad domain",
			input:   "10.1.1.1,this.domain.does.not.exist.invalid",
			wantErr: true,
		},
		{
			name:    "one valid domain one bad domain",
			input:   "google.com,this.domain.does.not.exist.invalid",
			wantErr: true,
		},
		{
			name:    "invalid ip with valid domain",
			input:   "bing.com,10.1.1.1/33",
			wantErr: true,
		},
		{
			name:    "whitespace only errors",
			input:   "   ",
			wantErr: true,
		},

		{
			name:    "ip with port is invalid",
			input:   "10.1.1.1:80",
			wantErr: true,
		},
		{
			name:    "url scheme is invalid",
			input:   "https://google.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, hosts, err := TargetsFromStringWithDNSLookup(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (prefixes: %v, hosts: %v)", prefixes, hosts)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !allValid(prefixes) {
				t.Errorf("result contains invalid prefixes: %v", prefixes)
			}

			if len(prefixes) != tt.wantLen {
				t.Errorf("prefix count = %d, want = %d (prefixes: %v)", len(prefixes), tt.wantLen, prefixes)
			}

			if len(hosts) != tt.wantHosts {
				t.Errorf("hostname map len = %d, want = %d (hosts: %v)", len(hosts), tt.wantHosts, hosts)
			}

			// Hostname values in map
			for _, wantedHost := range tt.checkHostnames {
				found := false
				for _, v := range hosts {
					if v == wantedHost {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("hostname %q not found as a value in hosts map: %v", wantedHost, hosts)
				}
			}

			if hasDuplicates(prefixes) {
				t.Errorf("result contains duplicate prefixes: %v", prefixes)
			}
		})
	}
}

func TestPortsFromString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantPorts []uint // exact expected output (sorted, deduped)
		wantErr   bool
	}{
		// --- Single ports ---
		{
			name:      "single port",
			input:     "80",
			wantPorts: []uint{80},
		},
		{
			name:      "port 0",
			input:     "0",
			wantPorts: []uint{0},
		},
		{
			name:      "port 1",
			input:     "1",
			wantPorts: []uint{1},
		},
		{
			name:      "max port 65535",
			input:     "65535",
			wantPorts: []uint{65535},
		},

		// --- Multiple ports ---
		{
			name:      "three ports",
			input:     "22,80,443",
			wantPorts: []uint{22, 80, 443},
		},
		{
			name:      "ports given",
			input:     "443,22,80",
			wantPorts: []uint{22, 80, 443},
		},
		{
			name:      "duplicate ports",
			input:     "80,80",
			wantPorts: []uint{80},
		},
		{
			name:      "many duplicates",
			input:     "80,80,80,80",
			wantPorts: []uint{80},
		},
		{
			name:      "duplicates across positions",
			input:     "22,80,22",
			wantPorts: []uint{22, 80},
		},

		// --- Ranges ---
		{
			name:      "simple range",
			input:     "1-5",
			wantPorts: []uint{1, 2, 3, 4, 5},
		},
		{
			name:      "range and single port",
			input:     "1-5,22",
			wantPorts: []uint{1, 2, 3, 4, 5, 22},
		},
		{
			name:      "multiple ranges",
			input:     "1-3,80-82",
			wantPorts: []uint{1, 2, 3, 80, 81, 82},
		},
		{
			name:      "range mixed with singles",
			input:     "1-5,22,80-81",
			wantPorts: []uint{1, 2, 3, 4, 5, 22, 80, 81},
		},
		{
			name:      "range of one (start == end)",
			input:     "80-80",
			wantPorts: []uint{80},
		},
		{
			name:      "range overlapping with explicit port deduplicated",
			input:     "1-5,3",
			wantPorts: []uint{1, 2, 3, 4, 5},
		},
		{
			name:      "overlapping ranges deduplicated",
			input:     "1-5,3-7",
			wantPorts: []uint{1, 2, 3, 4, 5, 6, 7},
		},
		{
			name:      "adjacent ranges merged in output",
			input:     "1-3,4-6",
			wantPorts: []uint{1, 2, 3, 4, 5, 6},
		},
		{
			name:      "range up to max port",
			input:     "65533-65535",
			wantPorts: []uint{65533, 65534, 65535},
		},
		{
			name:      "upper limit only",
			input:     "-5",
			wantPorts: []uint{0, 1, 2, 3, 4, 5},
		},

		// --- Whitespace ---
		{
			name:      "spaces around commas",
			input:     "22, 80, 443",
			wantPorts: []uint{22, 80, 443},
		},
		{
			name:      "spaces around range",
			input:     "1 - 5",
			wantPorts: []uint{1, 2, 3, 4, 5},
		},

		// --- Errors: invalid tokens ---
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "non-numeric token",
			input:   "http",
			wantErr: true,
		},
		{
			name:    "non-numeric mixed with valid",
			input:   "80,http",
			wantErr: true,
		},
		{
			name:    "float",
			input:   "80.5",
			wantErr: true,
		},
		{
			name:    "port above 65535",
			input:   "65536",
			wantErr: true,
		},
		{
			name:    "way above max port",
			input:   "99999",
			wantErr: true,
		},
		{
			name:    "trailing comma",
			input:   "80,",
			wantErr: true,
		},
		{
			name:    "leading comma",
			input:   ",80",
			wantErr: true,
		},
		{
			name:    "double comma",
			input:   "80,,443",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},

		// --- Errors: invalid ranges ---
		{
			name:    "descending range",
			input:   "10-5",
			wantErr: true,
		},
		{
			name:    "range with non-numeric start",
			input:   "abc-10",
			wantErr: true,
		},
		{
			name:    "range with non-numeric end",
			input:   "10-abc",
			wantErr: true,
		},
		{
			name:    "range end above 65535",
			input:   "80-65536",
			wantErr: true,
		},
		{
			name:    "range start above 65535",
			input:   "65536-65537",
			wantErr: true,
		},
		{
			name:    "range with negative start",
			input:   "-1-5",
			wantErr: true,
		},
		{
			name:    "range with three parts",
			input:   "1-5-10",
			wantErr: true,
		},
		{
			name:    "empty range end",
			input:   "5-",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PortsFromString(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (result: %v)", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != len(tt.wantPorts) {
				t.Fatalf("len = %d, want %d\n  got:  %v\n  full: %v", len(got), len(tt.wantPorts), got, tt.wantPorts)
			}

			if tt.wantPorts != nil {
				for i := range got {
					if got[i] != tt.wantPorts[i] {
						t.Errorf("port[%d] = %d, want %d\n  got:  %v\n  full: %v", i, got[i], tt.wantPorts[i], got, tt.wantPorts)
					}
				}
			}

			if hasDuplicates(got) {
				t.Errorf("result contains duplicate ports: %v", got)
			}
		})
	}
}

func hasDuplicates[T comparable](ps []T) bool {
	seen := make(map[T]struct{})
	for _, p := range ps {
		if _, alreadySeen := seen[p]; alreadySeen {
			return true
		}
		seen[p] = struct{}{}
	}
	return false
}

func allValid(ps []netip.Prefix) bool {
	for _, p := range ps {
		if !p.IsValid() {
			return false
		}
	}
	return true
}

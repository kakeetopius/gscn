package netutils

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
)

type InterfaceIndex int

type MockInterfaceProvider struct {
	// List of mock interfaces
	InterfaceSet []net.Interface

	// Map with all  of the interfaces addresses.
	InterfacesAddrs map[InterfaceIndex][]net.Addr

	Err error
}

func (m MockInterfaceProvider) Interfaces() ([]net.Interface, error) {
	return m.InterfaceSet, m.Err
}

func (m MockInterfaceProvider) AddrsOf(iface *net.Interface) ([]net.Addr, error) {
	return m.InterfacesAddrs[InterfaceIndex(iface.Index)], m.Err
}

func (m MockInterfaceProvider) InterfaceByIndex(index InterfaceIndex) (*net.Interface, error) {
	for _, currentiface := range m.InterfaceSet {
		if currentiface.Index == int(index) {
			return &currentiface, m.Err
		}
	}

	return nil, fmt.Errorf("Interface with index %v not found", index)
}

var mock = MockInterfaceProvider{
	InterfaceSet: []net.Interface{
		{
			Name:  "lo",
			Index: 0,
			Flags: net.FlagLoopback,
		},
		{
			Name:  "eth1",
			Index: 1,
			Flags: net.FlagUp | net.FlagRunning,
		},
		{
			Name:  "eth2",
			Index: 2,
			Flags: net.FlagUp,
		},
		{
			Name:  "eth3",
			Index: 3,
			Flags: net.FlagRunning,
		},
		{
			Name:  "eth4",
			Index: 4,
			Flags: net.FlagUp,
		},
	},
	InterfacesAddrs: map[InterfaceIndex][]net.Addr{
		0: {
			IPNet("127.0.0.1/24"),
			IPNet("::1/64"),
		},
		1: {
			IPNet("192.168.22.1/24"),
			IPNet("10.1.1.1/24"),
			IPNet("172.16.1.1/24"),
			IPNet("2001:db8:85a3::8a2e:370:7334/64"),
		},
		2: {
			IPNet("192.168.10.1/24"),
			IPNet("10.0.0.1/24"),
			IPNet("172.16.2.2/24"),
			IPNet("2607:f8b0:4005:800::200e/64"),
		},
		3: {
			IPNet("192.168.15.1/24"),
			IPNet("10.2.2.1/24"),
			IPNet("172.16.5.1/24"),
			IPNet("2404:6800:4003:c00::6a/64"),
		},
	},

	Err: nil,
}

func TestGetIfaceByIP(t *testing.T) {
	tests := []struct {
		IP      string
		want    InterfaceIndex
		wantErr bool
	}{
		{"10.1.1.1/24", 1, false},
		{"192.168.10.1/24", 2, false},
		{"172.16.5.1/24", 3, false},
		{"172.16.7.1/24", 2, true},
		{"fe80::b4aa:32ff:fe19:6c02/64", 3, true},
		{"2404:6800:4003:c00::6a/64", 3, false},
		{"2001:db8:85a3::8a2e:370:7334/64", 1, false},
		{"2001:abcd:acad::1/64", 2, true},
		{"127.0.0.1/24", 0, false},
		{"::1/64", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.IP, func(t *testing.T) {
			ip, err := netip.ParsePrefix(tt.IP)
			if err != nil {
				t.Fatal(err)
			}
			ifaceGot, err := GetIfaceByIP(mock, ip.Addr())
			if err != nil {
				if !tt.wantErr {
					t.Fatal("GetIfaceByIP() failed: ", err)
				}
				t.Log("Expected an error and got: ", err)
				return
			}

			if tt.wantErr {
				t.Fatal("GetIfaceByIP() succeeded unexpectedly")
				return
			}
			if ifaceGot.Index != int(tt.want) {
				expectedIface, _ := mock.InterfaceByIndex(tt.want)
				t.Fatalf("Expected: %v got %v", expectedIface.Name, ifaceGot.Name)
			}
		})
	}
}

func TestGetFirstIfaceIPNet(t *testing.T) {
	tests := []struct {
		index   InterfaceIndex
		want    string
		ip6     bool
		wantErr bool
	}{
		{1, "192.168.22.1/24", false, false},
		{1, "2001:db8:85a3::8a2e:370:7334/64", true, false},
		{2, "192.168.10.1/24", false, false},
		{2, "2607:f8b0:4005:800::200e/64", true, false},
		{3, "192.168.15.1/24", false, false},
		{3, "2404:6800:4003:c00::6a/64", true, false},
		{4, "10.1.1.1/24", false, true},
	}

	for _, tt := range tests {
		iface, err := mock.InterfaceByIndex(tt.index)
		if err != nil {
			t.Log(err)
			continue
		}
		var testName string
		if tt.ip6 {
			testName = fmt.Sprintf("%v for ip6", iface.Name)
		} else {
			testName = fmt.Sprintf("%v for ip4", iface.Name)
		}
		t.Run(testName, func(t *testing.T) {
			expectedAddr, err := netip.ParsePrefix(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			addrGot, err := GetFirstIfaceIPNet(mock, iface, tt.ip6)
			if err != nil {
				if !tt.wantErr {
					t.Fatal("GetFirstIfaceIPNet() failed: ", err)
				}
				t.Log("Expected an error and got: ", err)
				return
			}
			if tt.wantErr {
				t.Fatal("GetFirstIfaceIPNet() succeeded unexpectedly")
				return
			}

			if expectedAddr != *addrGot {
				t.Fatalf("Expected: %v, got: %v", expectedAddr, addrGot)
			}
		})
	}
}

// func TestVerifyandGetIfaceDetails(t *testing.T) {
// 	tests := []struct {
// 		ifaceIndex      InterfaceIndex
// 		destIP          string
// 		ip6             bool
// 		expectedIfaceIP string
// 		wantErr         bool
// 	}{
// 		{0, "10.1.1.1/24", false, "127.0.0.1/24", true},
// 		{0, "::1/64", true, "::1/64", true},
// 		{1, "192.168.22.1/24", false, "192.168.22.1/24", false},
// 		{1, "10.1.1.1/24", false, "10.1.1.1/24", false},
// 		{1, "172.16.1.1/24", false, "172.16.1.1/24", false},
// 		{1, "10.3.3.1/24", false, "192.168.22.1/24", false},
// 		{1, "2001:db8:85a3::8a2e:370:7334/64", true, "2001:db8:85a3::8a2e:370:7334/64", false},
// 		{2, "192.168.10.1/24", false, "192.168.10.1/24", true},
// 		{2, "10.0.0.1/24", false, "10.0.0.1/24", true},
// 	}
// 	for _, tt := range tests {
// 		iface, err := mock.InterfaceByIndex(tt.ifaceIndex)
// 		if err != nil {
// 			t.Fatal(err)
// 			continue
// 		}
// 		testName := fmt.Sprintf("%v for target %v", iface.Name, tt.destIP)
// 		t.Run(testName, func(t *testing.T) {
// 			dest, err := netip.ParsePrefix(tt.destIP)
// 			if err != nil {
// 				t.Fatal(err)
// 				return
// 			}
// 			got, gotErr := VerifyInterface(mock, iface, []netip.Prefix{dest}, tt.ip6)
// 			if gotErr != nil {
// 				if !tt.wantErr {
// 					t.Errorf("VerifyandGetIfaceDetails() failed: %v", gotErr)
// 				}
// 				t.Log("Expected an error and got: ", gotErr)
// 				return
// 			}
// 			if tt.wantErr {
// 				t.Fatal("VerifyandGetIfaceDetails() succeeded unexpectedly")
// 				return
// 			}
// 			expectedIfaceIP, err := netip.ParsePrefix(tt.expectedIfaceIP)
// 			if err != nil {
// 				t.Fatal(err)
// 				return
// 			}
// 			if expectedIfaceIP.Addr() != got.IfaceIPtoUse {
// 				t.Errorf("VerifyandGetIfaceDetails() returned %v, but wanted %v", got.IfaceIPtoUse, expectedIfaceIP.Addr())
// 			}
// 		})
// 	}
// }

func IPNet(s string) *net.IPNet {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		fmt.Println("Error parsing one of the addresses in mock interface provider: ", err)
		os.Exit(-1)
	}

	return &net.IPNet{
		IP:   ip,
		Mask: ipnet.Mask,
	}
}

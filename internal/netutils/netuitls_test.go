package netutils

import (
	"fmt"
	"net"
	"net/netip"
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
			return &currentiface, nil
		}
	}

	return nil, fmt.Errorf("Interface with index %v not found", index)
}

var mock = MockInterfaceProvider{
	InterfaceSet: []net.Interface{
		{
			Name:  "eth0",
			Index: 0,
			Flags: 0,
		},
		{
			Name:  "eth1",
			Index: 1,
			Flags: 0,
		},
		{
			Name:  "eth2",
			Index: 2,
			Flags: 0,
		},
	},
	InterfacesAddrs: map[InterfaceIndex][]net.Addr{
		0: {
			IPNet("192.168.22.1/24"),
			IPNet("10.1.1.1/24"),
			IPNet("172.16.1.1/24"),
		},
		1: {
			IPNet("192.168.10.1/24"),
			IPNet("10.0.0.1/24"),
			IPNet("172.16.2.2/24"),
		},
		2: {
			IPNet("192.168.15.1/24"),
			IPNet("10.2.2.1/24"),
			IPNet("172.16.5.1/24"),
		},
	},

	Err: nil,
}

func TestGetIfaceByIP(t *testing.T) {
	tests := []struct {
		IP            string
		expected      InterfaceIndex
		errorExpected bool
	}{
		{"10.1.1.1/24", 0, false},
		{"192.168.10.1/24", 1, false},
		{"172.16.5.1/24", 2, false},
		{"172.16.7.1/24", 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.IP, func(t *testing.T) {
			ip, err := netip.ParsePrefix(tt.IP)
			if err != nil {
				t.Fatal(err)
			}
			ifaceGot, err := GetIfaceByIP(mock, ip.Addr())
			if tt.errorExpected && err == nil {
				t.Fatal("Expected an error but got none")
			} else if err != nil && tt.errorExpected {
				t.Log("Expected an error and got: ", err)
				return
			} else if err != nil {
				t.Fatal(err)
			}

			if ifaceGot.Index != int(tt.expected) {
				expectedIface, _ := mock.InterfaceByIndex(tt.expected)
				t.Fatalf("Expected: %v got %v", expectedIface.Name, ifaceGot.Name)
			}
		})
	}
}

func IPNet(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		fmt.Println(err)
	}
	return ipnet
}

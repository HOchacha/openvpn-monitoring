package geoip

import (
	"net/netip"
	"testing"
)

func TestIsGlobal(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"10.8.0.6", false},    // VPN-internal
		{"192.168.1.1", false}, // private
		{"172.16.5.4", false},  // private
		{"127.0.0.1", false},   // loopback
		{"169.254.1.1", false}, // link-local
		{"0.0.0.0", false},     // unspecified
		{"224.0.0.1", false},   // multicast
		{"fe80::1", false},     // link-local v6
		{"::1", false},         // loopback v6
		{"fd00::1", false},     // unique local v6 (private)
	}
	for _, c := range cases {
		addr := netip.MustParseAddr(c.addr)
		if got := isGlobal(addr); got != c.want {
			t.Errorf("isGlobal(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
}

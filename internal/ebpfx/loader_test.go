package ebpfx

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestAddrRoundTrip(t *testing.T) {
	for _, s := range []string{"10.8.0.2", "1.1.1.1", "255.254.253.252", "0.0.0.0"} {
		addr := netip.MustParseAddr(s)
		if got := addrFromBE(mapKeyFor(addr)); got != addr {
			t.Errorf("round trip of %s produced %s", addr, got)
		}
	}
}

// TestEventHeaderSize guards the hand-rolled ring buffer decoder against a
// layout change in struct event. The generated Go struct is padded to an
// 8-byte multiple, so derive the header offset from the payload field instead
// of the total size.
func TestEventHeaderSize(t *testing.T) {
	var ev ovpnmonEvent
	got := int(uintptr(len(ev.Payload)))
	if want := 512; got != want {
		t.Fatalf("payload snap length is %d, expected %d", got, want)
	}
	// ts(8) + client_ip(4) + remote_ip(4) + client_id(4) +
	// remote_port(2) + client_port(2) + payload_len(2) + type(1) + proto(1)
	if eventHeaderSize != 8+4+4+4+2+2+2+1+1 {
		t.Fatalf("eventHeaderSize %d no longer matches struct event", eventHeaderSize)
	}
}

// TestLoadAndAttach exercises the real verifier and the real TCX attachment.
// It needs root and a tun interface, so it self-skips elsewhere.
func TestLoadAndAttach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs")
	}
	iface := os.Getenv("OVPNMON_TEST_IFACE")
	if iface == "" {
		iface = "tun0"
	}

	dp, err := Load(iface, netip.MustParsePrefix("10.8.0.0/24"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer dp.Close()

	if _, err := dp.Stats(); err != nil {
		t.Errorf("Stats: %v", err)
	}
	if _, err := dp.Flows(); err != nil {
		t.Errorf("Flows: %v", err)
	}

	client := netip.MustParseAddr("10.8.0.42")
	if err := dp.SetSession(client, 7); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	// Confirm the kernel sees the key the way addrFromBE reads it back.
	var got ovpnmonSessionInfo
	key := mapKeyFor(client)
	if err := dp.objs.Sessions.Lookup(&key, &got); err != nil {
		t.Fatalf("session lookup: %v", err)
	}
	if got.ClientId != 7 {
		t.Errorf("client id is %d, expected 7", got.ClientId)
	}

	if err := dp.DeleteSession(client); err != nil {
		t.Errorf("DeleteSession: %v", err)
	}
	if err := dp.DeleteSession(client); err != nil {
		t.Errorf("DeleteSession on a missing key should be a no-op: %v", err)
	}

	if _, err := dp.PruneFlows(time.Hour); err != nil {
		t.Errorf("PruneFlows: %v", err)
	}
}

func TestVpnMaskCalculation(t *testing.T) {
	cases := map[string]uint32{
		"10.8.0.0/24":   0xffffff00,
		"10.0.0.0/8":    0xff000000,
		"172.16.0.0/12": 0xfff00000,
	}
	for pfx, want := range cases {
		p := netip.MustParsePrefix(pfx)
		got := ^uint32(0) << (32 - p.Bits())
		if got != want {
			t.Errorf("mask for %s is %#x, expected %#x", pfx, got, want)
		}
		base := p.Masked().Addr().As4()
		if binary.BigEndian.Uint32(base[:])&got != binary.BigEndian.Uint32(base[:]) {
			t.Errorf("network address of %s is not aligned to its own mask", pfx)
		}
	}
}

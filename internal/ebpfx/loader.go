package ebpfx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Event types, mirroring enum event_type in bpf/ovpnmon.bpf.c.
const (
	EventConnect uint8 = 1
	EventDNS     uint8 = 2
	EventSNI     uint8 = 3
	EventHTTP    uint8 = 4
)

// Indices into the probe_stats map, mirroring enum stat_slot.
const (
	statPackets = iota
	statNotIPv4
	statNotVPN
	statEvents
	statEventsLost
	statTruncated
	numStats
)

// eventHeaderSize is offsetof(struct event, payload).
const eventHeaderSize = 28

// Dataplane is a loaded and attached instance of the ovpnmon eBPF programs.
type Dataplane struct {
	objs   ovpnmonObjects
	links  []link.Link
	reader *ringbuf.Reader

	// bootTime anchors the kernel's monotonic timestamps to wall clock.
	bootTime time.Time
}

// Flow is one aggregated {client, destination} conversation.
type Flow struct {
	ClientIP    netip.Addr `json:"client_ip"`
	RemoteIP    netip.Addr `json:"remote_ip"`
	RemotePort  uint16     `json:"remote_port"`
	Proto       uint8      `json:"proto"`
	ClientID    uint32     `json:"client_id"`
	TxBytes     uint64     `json:"tx_bytes"`
	TxPackets   uint64     `json:"tx_packets"`
	RxBytes     uint64     `json:"rx_bytes"`
	RxPackets   uint64     `json:"rx_packets"`
	Connections uint32     `json:"connections"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
}

// Event is one ring buffer record.
type Event struct {
	Type       uint8
	Proto      uint8
	ClientIP   netip.Addr
	RemoteIP   netip.Addr
	ClientID   uint32
	RemotePort uint16
	ClientPort uint16
	Timestamp  time.Time
	Payload    []byte
}

// ProbeStats reports what the kernel side has seen, for self-observability.
type ProbeStats struct {
	Packets    uint64 `json:"packets"`
	NotIPv4    uint64 `json:"not_ipv4"`
	NotVPN     uint64 `json:"not_vpn"`
	Events     uint64 `json:"events"`
	EventsLost uint64 `json:"events_lost"`
	Truncated  uint64 `json:"truncated"`
}

// Load compiles-in the dataplane, pins the VPN subnet into its read-only data,
// and attaches it to both directions of iface using TCX.
func Load(iface string, vpnNet netip.Prefix) (*Dataplane, error) {
	if !vpnNet.Addr().Is4() {
		return nil, fmt.Errorf("vpn subnet %s is not IPv4", vpnNet)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising memlock limit: %w", err)
	}

	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("looking up interface %q: %w", iface, err)
	}

	spec, err := loadOvpnmon()
	if err != nil {
		return nil, fmt.Errorf("loading embedded eBPF object: %w", err)
	}

	// Host byte order, matching the kernel side's bpf_ntohl() comparison.
	base := vpnNet.Masked().Addr().As4()
	netAddr := binary.BigEndian.Uint32(base[:])
	mask := ^uint32(0) << (32 - vpnNet.Bits())
	if vpnNet.Bits() == 0 {
		mask = 0
	}
	if err := spec.Variables["vpn_net"].Set(netAddr); err != nil {
		return nil, fmt.Errorf("setting vpn_net: %w", err)
	}
	if err := spec.Variables["vpn_mask"].Set(mask); err != nil {
		return nil, fmt.Errorf("setting vpn_mask: %w", err)
	}

	d := &Dataplane{bootTime: bootTime()}
	if err := spec.LoadAndAssign(&d.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected program: %+v", ve)
		}
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	attach := func(prog *ebpf.Program, at ebpf.AttachType, what string) error {
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: dev.Index,
			Program:   prog,
			Attach:    at,
		})
		if err != nil {
			return fmt.Errorf("attaching %s to %s: %w", what, iface, err)
		}
		d.links = append(d.links, l)
		return nil
	}

	if err := attach(d.objs.OvpnmonIngress, ebpf.AttachTCXIngress, "ingress"); err != nil {
		d.Close()
		return nil, err
	}
	if err := attach(d.objs.OvpnmonEgress, ebpf.AttachTCXEgress, "egress"); err != nil {
		d.Close()
		return nil, err
	}

	d.reader, err = ringbuf.NewReader(d.objs.Events)
	if err != nil {
		d.Close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}

	return d, nil
}

// bootTime derives the wall-clock instant that CLOCK_MONOTONIC counts from, so
// bpf_ktime_get_ns() values can be reported as real timestamps.
func bootTime() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(ts.Nano()))
}

func (d *Dataplane) monoToWall(ns uint64) time.Time {
	return d.bootTime.Add(time.Duration(ns))
}

// SetSession tells the kernel which OpenVPN client id owns a VPN-internal
// address, so flows are tagged at the point they are counted.
func (d *Dataplane) SetSession(vpnIP netip.Addr, clientID uint32) error {
	if !vpnIP.Is4() {
		return fmt.Errorf("session address %s is not IPv4", vpnIP)
	}
	key := mapKeyFor(vpnIP)
	val := ovpnmonSessionInfo{ClientId: clientID}
	return d.objs.Sessions.Update(&key, &val, ebpf.UpdateAny)
}

// DeleteSession removes a mapping once a client disconnects.
func (d *Dataplane) DeleteSession(vpnIP netip.Addr) error {
	if !vpnIP.Is4() {
		return nil
	}
	key := mapKeyFor(vpnIP)
	err := d.objs.Sessions.Delete(&key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// Flows snapshots every tracked conversation.
func (d *Dataplane) Flows() ([]Flow, error) {
	var (
		key  ovpnmonFlowKey
		stat ovpnmonFlowStat
		out  []Flow
	)
	it := d.objs.Flows.Iterate()
	for it.Next(&key, &stat) {
		out = append(out, Flow{
			ClientIP:    addrFromBE(key.ClientIp),
			RemoteIP:    addrFromBE(key.RemoteIp),
			RemotePort:  key.RemotePort,
			Proto:       key.Proto,
			ClientID:    stat.ClientId,
			TxBytes:     stat.TxBytes,
			TxPackets:   stat.TxPackets,
			RxBytes:     stat.RxBytes,
			RxPackets:   stat.RxPackets,
			Connections: stat.Connections,
			FirstSeen:   d.monoToWall(stat.FirstNs),
			LastSeen:    d.monoToWall(stat.LastNs),
		})
	}
	return out, it.Err()
}

// PruneFlows drops entries untouched for longer than idle, keeping the map
// representative of what is happening now rather than what ever happened.
func (d *Dataplane) PruneFlows(idle time.Duration) (int, error) {
	cutoff := time.Now().Add(-idle)

	var (
		key    ovpnmonFlowKey
		stat   ovpnmonFlowStat
		stale  []ovpnmonFlowKey
		purged int
	)
	it := d.objs.Flows.Iterate()
	for it.Next(&key, &stat) {
		if d.monoToWall(stat.LastNs).Before(cutoff) {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return 0, err
	}
	for i := range stale {
		if err := d.objs.Flows.Delete(&stale[i]); err == nil {
			purged++
		}
	}
	return purged, nil
}

// Stats sums the per-CPU probe counters.
func (d *Dataplane) Stats() (ProbeStats, error) {
	var ps ProbeStats
	fields := []*uint64{
		&ps.Packets, &ps.NotIPv4, &ps.NotVPN,
		&ps.Events, &ps.EventsLost, &ps.Truncated,
	}
	for i := range fields {
		var percpu []uint64
		if err := d.objs.ProbeStats.Lookup(uint32(i), &percpu); err != nil {
			return ps, fmt.Errorf("reading probe stat %d: %w", i, err)
		}
		var sum uint64
		for _, v := range percpu {
			sum += v
		}
		*fields[i] = sum
	}
	return ps, nil
}

// ReadEvent blocks until the next ring buffer record arrives. It returns
// os.ErrClosed once Close has been called.
func (d *Dataplane) ReadEvent() (Event, error) {
	rec, err := d.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return Event{}, os.ErrClosed
		}
		return Event{}, err
	}
	if len(rec.RawSample) < eventHeaderSize {
		return Event{}, fmt.Errorf("short event record: %d bytes", len(rec.RawSample))
	}

	b := rec.RawSample
	ev := Event{
		Timestamp:  d.monoToWall(binary.LittleEndian.Uint64(b[0:8])),
		ClientIP:   addrFromBE(binary.LittleEndian.Uint32(b[8:12])),
		RemoteIP:   addrFromBE(binary.LittleEndian.Uint32(b[12:16])),
		ClientID:   binary.LittleEndian.Uint32(b[16:20]),
		RemotePort: binary.LittleEndian.Uint16(b[20:22]),
		ClientPort: binary.LittleEndian.Uint16(b[22:24]),
		Type:       b[26],
		Proto:      b[27],
	}
	plen := int(binary.LittleEndian.Uint16(b[24:26]))
	if plen > len(b)-eventHeaderSize {
		plen = len(b) - eventHeaderSize
	}
	if plen > 0 {
		ev.Payload = append([]byte(nil), b[eventHeaderSize:eventHeaderSize+plen]...)
	}
	return ev, nil
}

// Close detaches the programs and releases every resource.
func (d *Dataplane) Close() error {
	var errs []error
	if d.reader != nil {
		errs = append(errs, d.reader.Close())
	}
	for _, l := range d.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, d.objs.Close())
	return errors.Join(errs...)
}

// addrFromBE converts an in-kernel network-byte-order address to a netip.Addr.
// The kernel stores raw iphdr fields, so the u32 read back through a
// little-endian host already holds the address bytes in wire order.
func addrFromBE(v uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// mapKeyFor is the inverse of addrFromBE: the u32 the kernel will compare
// against iphdr.saddr/daddr for this address.
func mapKeyFor(a netip.Addr) uint32 {
	b := a.As4()
	return binary.LittleEndian.Uint32(b[:])
}

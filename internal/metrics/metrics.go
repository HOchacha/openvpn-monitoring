// Package metrics exposes the collector's snapshot as Prometheus metrics.
//
// Metrics are produced on scrape from the latest snapshot rather than kept as
// long-lived counters, because the underlying facts - who is connected, which
// destinations they are using - come and go. That also keeps a disconnected
// client from lingering as a stale series forever.
package metrics

import (
	"sort"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ubuntu/openvpn-monitoring/internal/collector"
	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

// SnapshotSource is the part of the collector this package needs.
type SnapshotSource interface {
	Snapshot() collector.Snapshot
}

// Exporter turns snapshots into metrics.
type Exporter struct {
	src SnapshotSource

	// topDestinations bounds label cardinality. Every destination a client
	// touches would otherwise become its own series, and a single busy user
	// browsing the web can produce thousands per minute.
	topDestinations int

	sessionsTotal   *prometheus.Desc
	sessionInfo     *prometheus.Desc
	sessionDuration *prometheus.Desc
	tunnelBytes     *prometheus.Desc
	flowBytes       *prometheus.Desc
	destBytes       *prometheus.Desc
	destConnections *prometheus.Desc
	probePackets    *prometheus.Desc
	probeEvents     *prometheus.Desc
	probeLost       *prometheus.Desc
	flowCount       *prometheus.Desc
	namesCached     *prometheus.Desc
	mgmtUp          *prometheus.Desc
}

// NewExporter builds an exporter. topDestinations of zero disables per
// destination series entirely.
func NewExporter(src SnapshotSource, topDestinations int) *Exporter {
	return &Exporter{
		src:             src,
		topDestinations: topDestinations,

		sessionsTotal: prometheus.NewDesc(
			"openvpn_sessions",
			"Number of clients currently connected.",
			nil, nil),
		sessionInfo: prometheus.NewDesc(
			"openvpn_session_info",
			"Constant 1 per connected client, labelled with its identity.",
			[]string{"common_name", "virtual_ip", "real_address", "cipher"}, nil),
		sessionDuration: prometheus.NewDesc(
			"openvpn_session_duration_seconds",
			"How long each client has been connected.",
			[]string{"common_name", "virtual_ip"}, nil),
		tunnelBytes: prometheus.NewDesc(
			"openvpn_tunnel_bytes",
			"Bytes counted by OpenVPN itself for the encrypted tunnel.",
			[]string{"common_name", "virtual_ip", "direction"}, nil),
		flowBytes: prometheus.NewDesc(
			"openvpn_client_bytes",
			"Plaintext bytes observed inside the tunnel by the eBPF probe.",
			[]string{"common_name", "virtual_ip", "direction"}, nil),
		destBytes: prometheus.NewDesc(
			"openvpn_destination_bytes",
			"Bytes exchanged with one destination, for the busiest destinations per client.",
			[]string{"common_name", "hostname", "remote_ip", "port", "proto", "direction"}, nil),
		destConnections: prometheus.NewDesc(
			"openvpn_destination_connections",
			"TCP connections opened to one destination, for the busiest destinations per client.",
			[]string{"common_name", "hostname", "remote_ip", "port", "proto"}, nil),
		probePackets: prometheus.NewDesc(
			"openvpn_probe_packets",
			"Packets inspected by the eBPF probe since it was attached.",
			nil, nil),
		probeEvents: prometheus.NewDesc(
			"openvpn_probe_events",
			"Payload and connection events delivered to userspace.",
			nil, nil),
		probeLost: prometheus.NewDesc(
			"openvpn_probe_events_lost",
			"Events dropped because the ring buffer was full.",
			nil, nil),
		flowCount: prometheus.NewDesc(
			"openvpn_tracked_flows",
			"Entries currently held in the kernel flow map.",
			nil, nil),
		namesCached: prometheus.NewDesc(
			"openvpn_resolved_names",
			"Destination names currently cached.",
			nil, nil),
		mgmtUp: prometheus.NewDesc(
			"openvpn_management_up",
			"1 when the OpenVPN management interface is reachable.",
			nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		e.sessionsTotal, e.sessionInfo, e.sessionDuration, e.tunnelBytes,
		e.flowBytes, e.destBytes, e.destConnections, e.probePackets,
		e.probeEvents, e.probeLost, e.flowCount, e.namesCached, e.mgmtUp,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	snap := e.src.Snapshot()

	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	counter := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, labels...)
	}

	gauge(e.sessionsTotal, float64(len(snap.Sessions)))
	gauge(e.mgmtUp, boolToFloat(snap.MgmtHealthy))
	gauge(e.flowCount, float64(snap.FlowCount))
	gauge(e.namesCached, float64(snap.NamesCached))
	counter(e.probePackets, float64(snap.Probe.Packets))
	counter(e.probeEvents, float64(snap.Probe.Events))
	counter(e.probeLost, float64(snap.Probe.EventsLost))

	for _, s := range snap.Sessions {
		vip := s.VirtualIP.String()

		gauge(e.sessionInfo, 1, s.CommonName, vip, s.RealAddress, s.Cipher)
		if !s.ConnectedSince.IsZero() {
			gauge(e.sessionDuration,
				snap.UpdatedAt.Sub(s.ConnectedSince).Seconds(),
				s.CommonName, vip)
		}

		counter(e.tunnelBytes, float64(s.TunnelRx), s.CommonName, vip, "received")
		counter(e.tunnelBytes, float64(s.TunnelTx), s.CommonName, vip, "sent")
		counter(e.flowBytes, float64(s.FlowTx), s.CommonName, vip, "upload")
		counter(e.flowBytes, float64(s.FlowRx), s.CommonName, vip, "download")

		if e.topDestinations <= 0 {
			continue
		}

		// Destinations arrive sorted by volume; take the head and merge the
		// rest into one "other" series so totals still add up.
		dests := s.Destinations
		var other collector.Destination
		if len(dests) > e.topDestinations {
			for _, d := range dests[e.topDestinations:] {
				other.TxBytes += d.TxBytes
				other.RxBytes += d.RxBytes
				other.Connections += d.Connections
			}
			dests = dests[:e.topDestinations]
		}

		for _, d := range dests {
			host := d.Hostname
			if host == "" {
				host = d.RemoteIP.String()
			}
			port := strconv.Itoa(int(d.Port))
			counter(e.destBytes, float64(d.TxBytes),
				s.CommonName, host, d.RemoteIP.String(), port, d.Proto, "upload")
			counter(e.destBytes, float64(d.RxBytes),
				s.CommonName, host, d.RemoteIP.String(), port, d.Proto, "download")
			if d.Connections > 0 {
				counter(e.destConnections, float64(d.Connections),
					s.CommonName, host, d.RemoteIP.String(), port, d.Proto)
			}
		}

		if other.TxBytes > 0 || other.RxBytes > 0 {
			counter(e.destBytes, float64(other.TxBytes),
				s.CommonName, "other", "", "", "", "upload")
			counter(e.destBytes, float64(other.RxBytes),
				s.CommonName, "other", "", "", "", "download")
		}
	}
}

// TopDestinationsOf is a helper for callers that want the same ordering the
// exporter uses.
func TopDestinationsOf(s collector.SessionView, n int) []collector.Destination {
	out := append([]collector.Destination(nil), s.Destinations...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].TxBytes+out[i].RxBytes > out[j].TxBytes+out[j].RxBytes
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// StoreSource is the part of the history store this package needs.
type StoreSource interface {
	Stats() store.Stats
}

// StoreExporter reports the health of the history write path. Dropped events
// and write errors are the signals that matter: they mean the audit trail has
// holes in it.
type StoreExporter struct {
	src StoreSource

	written *prometheus.Desc
	dropped *prometheus.Desc
	dests   *prometheus.Desc
	errors  *prometheus.Desc
	queue   *prometheus.Desc
	pruned  *prometheus.Desc
}

// NewStoreExporter builds an exporter for the history store.
func NewStoreExporter(src StoreSource) *StoreExporter {
	return &StoreExporter{
		src: src,
		written: prometheus.NewDesc("openvpn_history_events_written",
			"Observations committed to the history store.", nil, nil),
		dropped: prometheus.NewDesc("openvpn_history_events_dropped",
			"Observations discarded because the write queue was full.", nil, nil),
		dests: prometheus.NewDesc("openvpn_history_destinations_written",
			"Per-destination traffic rows committed to the history store.", nil, nil),
		errors: prometheus.NewDesc("openvpn_history_write_errors",
			"Failed history write transactions.", nil, nil),
		queue: prometheus.NewDesc("openvpn_history_queue_depth",
			"Observations waiting to be written.", nil, nil),
		pruned: prometheus.NewDesc("openvpn_history_rows_pruned",
			"Rows deleted by retention.", nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (e *StoreExporter) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		e.written, e.dropped, e.dests, e.errors, e.queue, e.pruned,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (e *StoreExporter) Collect(ch chan<- prometheus.Metric) {
	s := e.src.Stats()
	c := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v)
	}
	c(e.written, float64(s.EventsWritten))
	c(e.dropped, float64(s.EventsDropped))
	c(e.dests, float64(s.DestsWritten))
	c(e.errors, float64(s.WriteErrors))
	c(e.pruned, float64(s.RowsPruned))
	ch <- prometheus.MustNewConstMetric(e.queue, prometheus.GaugeValue, float64(s.QueueDepth))
}

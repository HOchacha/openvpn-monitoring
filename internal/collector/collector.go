// Package collector joins the three sources of truth into one view:
//
//	OpenVPN management : who is connected, and which VPN address they hold
//	eBPF flow map      : how much traffic went where
//	payload snapshots  : what those destinations are actually called
//
// The management interface owns identity, the kernel owns counters, and the
// resolver owns names. Nothing here re-derives a fact another layer already
// knows.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ubuntu/openvpn-monitoring/internal/ebpfx"
	"github.com/ubuntu/openvpn-monitoring/internal/enrich"
	"github.com/ubuntu/openvpn-monitoring/internal/mgmt"
	"github.com/ubuntu/openvpn-monitoring/internal/resolver"
	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

// Config controls the collector's timing and limits.
type Config struct {
	Interface    string
	VPNSubnet    netip.Prefix
	MgmtAddr     string
	MgmtPassword string
	PollInterval time.Duration
	ScrapeEvery  time.Duration
	FlowIdle     time.Duration
	NameTTL      time.Duration
	EventHistory int

	// Store, when set, receives a durable copy of sessions, per-destination
	// traffic and observations. Nil disables history entirely.
	Store *store.Store

	// Enricher, when set, names destinations in terms of the infrastructure
	// they belong to. Nil means destinations are reported exactly as observed.
	Enricher enrich.Provider
}

// Defaults fills in anything the caller left zero.
func (c *Config) Defaults() {
	if c.Interface == "" {
		c.Interface = "tun0"
	}
	if !c.VPNSubnet.IsValid() {
		c.VPNSubnet = netip.MustParsePrefix("10.8.0.0/24")
	}
	if c.MgmtAddr == "" {
		c.MgmtAddr = "127.0.0.1:7505"
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.ScrapeEvery <= 0 {
		c.ScrapeEvery = 2 * time.Second
	}
	if c.FlowIdle <= 0 {
		c.FlowIdle = 5 * time.Minute
	}
	if c.NameTTL <= 0 {
		c.NameTTL = 30 * time.Minute
	}
	if c.EventHistory <= 0 {
		c.EventHistory = 500
	}
}

// Destination is one place a client has been talking to.
type Destination struct {
	RemoteIP   netip.Addr `json:"remote_ip"`
	Hostname   string     `json:"hostname,omitempty"`
	NameSource string     `json:"name_source,omitempty"`
	Port       uint16     `json:"port"`
	Proto      string     `json:"proto"`
	Service    string     `json:"service,omitempty"`

	// Resource is what this address is in the operator's infrastructure,
	// when an enrichment provider recognises it.
	Resource *enrich.Resource `json:"resource,omitempty"`

	TxBytes     uint64    `json:"tx_bytes"`
	RxBytes     uint64    `json:"rx_bytes"`
	Packets     uint64    `json:"packets"`
	Connections uint32    `json:"connections"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// SessionView is a connected client plus everything observed about it.
type SessionView struct {
	CommonName     string     `json:"common_name"`
	Username       string     `json:"username,omitempty"`
	RealAddress    string     `json:"real_address"`
	VirtualIP      netip.Addr `json:"virtual_ip"`
	ClientID       uint32     `json:"client_id"`
	Cipher         string     `json:"cipher,omitempty"`
	ConnectedSince time.Time  `json:"connected_since"`
	Duration       string     `json:"duration"`
	// Encrypted totals OpenVPN itself counts for the tunnel.
	TunnelRx uint64 `json:"tunnel_bytes_received"`
	TunnelTx uint64 `json:"tunnel_bytes_sent"`

	// Plaintext totals the probe has accumulated inside the tunnel since this
	// session began. Monotonic: they do not fall when a flow expires.
	FlowTx uint64 `json:"flow_tx_bytes"`
	FlowRx uint64 `json:"flow_rx_bytes"`

	// Current throughput in bytes per second, measured across the last two
	// scrapes. Zero until a second sample exists.
	TxRate float64 `json:"tx_bytes_per_sec"`
	RxRate float64 `json:"rx_bytes_per_sec"`

	Destinations []Destination `json:"destinations"`
}

// LiveEvent is something worth showing the moment it happens.
type LiveEvent struct {
	Time       time.Time  `json:"time"`
	Kind       string     `json:"kind"`
	CommonName string     `json:"common_name,omitempty"`
	ClientIP   netip.Addr `json:"client_ip,omitempty"`
	RemoteIP   netip.Addr `json:"remote_ip,omitempty"`
	RemotePort uint16     `json:"remote_port,omitempty"`
	Proto      string     `json:"proto,omitempty"`
	Hostname   string     `json:"hostname,omitempty"`
	Detail     string     `json:"detail,omitempty"`
}

// Snapshot is the whole world as of one instant.
type Snapshot struct {
	UpdatedAt    time.Time        `json:"updated_at"`
	Interface    string           `json:"interface"`
	VPNSubnet    string           `json:"vpn_subnet"`
	MgmtHealthy  bool             `json:"mgmt_healthy"`
	MgmtError    string           `json:"mgmt_error,omitempty"`
	Sessions     []SessionView    `json:"sessions"`
	Probe        ebpfx.ProbeStats `json:"probe"`
	NamesCached  int              `json:"names_cached"`
	FlowCount    int              `json:"flow_count"`
	Unattributed []Destination    `json:"unattributed,omitempty"`
}

// Collector owns the background loops and the current snapshot.
type Collector struct {
	cfg   Config
	log   *slog.Logger
	dp    *ebpfx.Dataplane
	cache *resolver.Cache

	mu       sync.RWMutex
	sessions map[netip.Addr]mgmt.Session
	snapshot Snapshot
	history  []LiveEvent

	// dbSessions maps a live VPN address to its row in the history store.
	dbSessions map[netip.Addr]int64

	// prevFlows holds the counter values seen at the previous scrape, so the
	// store can be fed increments. Touched only by scrapeLoop.
	prevFlows map[flowKey]flowCounters

	// rates holds the previous scrape's totals per session, so a per-second
	// figure can be derived. The dashboard should not have to infer rate from
	// successive snapshots: a browser that reconnects would show a spike.
	rates map[netip.Addr]rateSample

	// totals accumulates those increments per live session. The kernel map is
	// a live view - entries expire and can be evicted - so summing it would
	// produce a figure that goes down, which is not a counter. Prometheus
	// reads these instead.
	totals map[netip.Addr]*sessionTotals

	subMu sync.Mutex
	subs  map[chan LiveEvent]struct{}

	// mgmtClient is the live management connection, kept so commands can be
	// sent from an HTTP handler. Nil whenever the connection is down.
	mgmtMu     sync.Mutex
	mgmtClient *mgmt.Client
}

// rateSample is one session's byte totals at a point in time.
type rateSample struct {
	tx, rx uint64
	at     time.Time
}

// flowKey identifies a conversation across scrapes.
type flowKey struct {
	client netip.Addr
	remote netip.Addr
	port   uint16
	proto  uint8
}

type flowCounters struct {
	tx, rx, packets uint64
	connections     uint32
}

// delta returns how much cur advanced beyond prev. A counter that went
// backwards means the kernel entry was evicted and recreated, so the whole of
// cur is new.
func (prev flowCounters) delta(cur flowCounters) flowCounters {
	step := func(was, now uint64) uint64 {
		if now < was {
			return now
		}
		return now - was
	}
	d := flowCounters{
		tx:      step(prev.tx, cur.tx),
		rx:      step(prev.rx, cur.rx),
		packets: step(prev.packets, cur.packets),
	}
	if cur.connections < prev.connections {
		d.connections = cur.connections
	} else {
		d.connections = cur.connections - prev.connections
	}
	return d
}

func (c flowCounters) isZero() bool {
	return c.tx == 0 && c.rx == 0 && c.packets == 0 && c.connections == 0
}

// maxTrackedDestinations bounds the per-session accumulator. A session that
// runs for weeks would otherwise grow one entry per destination ever touched.
const maxTrackedDestinations = 2000

// sessionTotals is everything one connected client has done so far.
type sessionTotals struct {
	tx, rx uint64
	dests  map[flowKey]*destTotals
}

type destTotals struct {
	remoteIP   netip.Addr
	port       uint16
	proto      uint8
	hostname   string
	nameSource string
	tx, rx     uint64
	packets    uint64
	conns      uint32
	firstSeen  time.Time
	lastSeen   time.Time
}

// add folds one scrape's increment into the running totals.
func (s *sessionTotals) add(k flowKey, d flowCounters, f ebpfx.Flow, host, src string) {
	s.tx += d.tx
	s.rx += d.rx

	e, ok := s.dests[k]
	if !ok {
		if len(s.dests) >= maxTrackedDestinations {
			s.evictOldest()
		}
		e = &destTotals{
			remoteIP: f.RemoteIP, port: f.RemotePort, proto: f.Proto,
			firstSeen: f.FirstSeen,
		}
		s.dests[k] = e
	}

	e.tx += d.tx
	e.rx += d.rx
	e.packets += d.packets
	e.conns += d.connections
	e.lastSeen = f.LastSeen
	if f.FirstSeen.Before(e.firstSeen) {
		e.firstSeen = f.FirstSeen
	}
	// A later flow without an SNI must not erase a name already learned.
	if host != "" {
		e.hostname, e.nameSource = host, src
	}
}

func (s *sessionTotals) evictOldest() {
	var oldestKey flowKey
	var oldest time.Time
	first := true
	for k, e := range s.dests {
		if first || e.lastSeen.Before(oldest) {
			oldestKey, oldest, first = k, e.lastSeen, false
		}
	}
	if !first {
		delete(s.dests, oldestKey)
	}
}

// New loads the dataplane and prepares the collector. Call Run to start it.
func New(cfg Config, log *slog.Logger) (*Collector, error) {
	cfg.Defaults()

	dp, err := ebpfx.Load(cfg.Interface, cfg.VPNSubnet)
	if err != nil {
		return nil, err
	}

	c := &Collector{
		cfg:        cfg,
		log:        log,
		dp:         dp,
		cache:      resolver.NewCache(cfg.NameTTL, 65536),
		sessions:   make(map[netip.Addr]mgmt.Session),
		dbSessions: make(map[netip.Addr]int64),
		prevFlows:  make(map[flowKey]flowCounters),
		totals:     make(map[netip.Addr]*sessionTotals),
		rates:      make(map[netip.Addr]rateSample),
		subs:       make(map[chan LiveEvent]struct{}),
		snapshot: Snapshot{
			Interface: cfg.Interface,
			VPNSubnet: cfg.VPNSubnet.String(),
			UpdatedAt: time.Now(),
		},
	}

	// Sessions left open by a previous run would otherwise look like clients
	// that never disconnected.
	if cfg.Store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if n, err := cfg.Store.CloseOrphanedSessions(ctx); err != nil {
			log.Warn("could not close orphaned history sessions", "error", err)
		} else if n > 0 {
			log.Info("closed sessions left open by a previous run", "count", n)
		}
	}

	return c, nil
}

// Close releases the dataplane.
func (c *Collector) Close() error { return c.dp.Close() }

// Run drives every loop until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	wg.Add(3)
	go func() { defer wg.Done(); c.eventLoop(ctx) }()
	go func() { defer wg.Done(); c.mgmtLoop(ctx) }()
	go func() { defer wg.Done(); c.scrapeLoop(ctx) }()

	<-ctx.Done()
	// Unblock the ring buffer reader, which does not take a context.
	_ = c.dp.Close()
	wg.Wait()
	return ctx.Err()
}

// ---------------------------------------------------------------- loops ---

// mgmtLoop keeps a management connection alive and polls it for sessions.
func (c *Collector) mgmtLoop(ctx context.Context) {
	backoff := time.Second

	for ctx.Err() == nil {
		err := c.runMgmtSession(ctx)
		if ctx.Err() != nil {
			return
		}

		c.setMgmtError(err)
		c.log.Warn("management connection lost, retrying",
			"error", err, "in", backoff)

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *Collector) runMgmtSession(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	client, err := mgmt.Dial(dialCtx, c.cfg.MgmtAddr, c.cfg.MgmtPassword)
	cancel()
	if err != nil {
		return err
	}
	defer client.Close()

	c.log.Info("connected to OpenVPN management interface", "addr", c.cfg.MgmtAddr)
	c.setMgmtError(nil)

	c.mgmtMu.Lock()
	c.mgmtClient = client
	c.mgmtMu.Unlock()
	defer func() {
		c.mgmtMu.Lock()
		c.mgmtClient = nil
		c.mgmtMu.Unlock()
	}()

	// Deliberately not enabling bytecount notifications. The numbers they
	// carry already arrive with each status poll, so subscribing only makes
	// the daemon push data nothing reads - and when the connection ends,
	// those pending writes fail with a broken pipe partway through OpenVPN's
	// management teardown. It serves one client at a time with a listen
	// backlog of 1, so a session it fails to clean up blocks every later
	// connection until OpenVPN itself restarts.

	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	// Reconnecting is not free: OpenVPN serves one management client at a
	// time, so churning connections is how the interface gets wedged. Ride out
	// transient stalls on the existing connection instead of dropping it at
	// the first slow poll.
	const maxPollFailures = 3
	failures := 0

	for {
		pollCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		sessions, err := client.Status(pollCtx)
		cancel()

		switch {
		case err == nil:
			failures = 0
			c.applySessions(sessions)
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			failures++
			if failures >= maxPollFailures {
				return fmt.Errorf("polling status failed %d times in a row: %w",
					failures, err)
			}
			c.log.Warn("management poll failed, keeping the connection",
				"attempt", failures, "of", maxPollFailures, "error", err)
		}

		select {
		case <-ticker.C:
		case err := <-client.Err():
			return err
		case note := <-client.Notifications():
			c.handleNotification(note)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Collector) handleNotification(n mgmt.Notification) {
	switch n.Kind {
	case "CLIENT":
		// >CLIENT:ESTABLISHED,<cid> and friends. Deliberately not surfaced:
		// they carry a client id and nothing else, status polling already
		// produces a named connect/disconnect for the same moment, and a
		// single disconnect emits enough of them to push the events that
		// matter out of the feed. Killing one client produced fifty.
		c.log.Debug("openvpn client notification", "body", n.Body)
	case "INFO", "BYTECOUNT_CLI", "BYTECOUNT":
		// Not interesting on its own; status polling carries the numbers.
	default:
		c.log.Debug("management notification", "kind", n.Kind, "body", n.Body)
	}
}

// applySessions reconciles the management view with the kernel session map.
func (c *Collector) applySessions(sessions []mgmt.Session) {
	next := make(map[netip.Addr]mgmt.Session, len(sessions))
	for _, s := range sessions {
		if s.VirtualIP.IsValid() {
			next[s.VirtualIP] = s
		}
	}

	c.mu.Lock()
	prev := c.sessions
	c.sessions = next
	c.mu.Unlock()

	for ip, s := range next {
		if _, existed := prev[ip]; !existed {
			c.log.Info("client connected",
				"common_name", s.CommonName, "virtual_ip", ip,
				"real_address", s.RealAddr)
			c.emit(LiveEvent{
				Time: time.Now(), Kind: "connect",
				CommonName: s.CommonName, ClientIP: ip,
				Detail: "from " + s.RealAddr,
			})
			c.openHistorySession(ip, s)
		}
		if err := c.dp.SetSession(ip, s.ClientID); err != nil {
			c.log.Warn("could not tag session in kernel map",
				"virtual_ip", ip, "error", err)
		}
	}

	for ip, s := range prev {
		if _, still := next[ip]; still {
			continue
		}
		c.log.Info("client disconnected",
			"common_name", s.CommonName, "virtual_ip", ip)
		c.emit(LiveEvent{
			Time: time.Now(), Kind: "disconnect",
			CommonName: s.CommonName, ClientIP: ip,
		})
		if err := c.dp.DeleteSession(ip); err != nil {
			c.log.Warn("could not clear session from kernel map",
				"virtual_ip", ip, "error", err)
		}
		c.closeHistorySession(ip, s)
		// A recycled address must not inherit the previous tenant's names.
		c.cache.Forget(ip)
	}
}

// openHistorySession records a new connection in the durable store.
func (c *Collector) openHistorySession(ip netip.Addr, s mgmt.Session) {
	if c.cfg.Store == nil {
		return
	}

	connected := s.ConnectedSince
	if connected.IsZero() {
		connected = time.Now()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id, err := c.cfg.Store.ResumeOrStartSession(ctx, store.Session{
		CommonName:  s.CommonName,
		Username:    s.Username,
		VirtualIP:   ip.String(),
		RealAddress: s.RealAddr,
		ClientID:    s.ClientID,
		Cipher:      s.Cipher,
		ConnectedAt: connected,
		TunnelRx:    s.BytesReceived,
		TunnelTx:    s.BytesSent,
	})
	if err != nil {
		c.log.Warn("could not record session start", "common_name", s.CommonName, "error", err)
		return
	}

	c.mu.Lock()
	c.dbSessions[ip] = id
	c.mu.Unlock()
}

// closeHistorySession finalises a disconnected client's record.
func (c *Collector) closeHistorySession(ip netip.Addr, s mgmt.Session) {
	if c.cfg.Store == nil {
		return
	}

	c.mu.Lock()
	id, ok := c.dbSessions[ip]
	delete(c.dbSessions, ip)
	// The accumulated totals belong to the session that just ended; a client
	// reconnecting onto the same address starts from zero.
	delete(c.totals, ip)
	delete(c.rates, ip)
	c.mu.Unlock()
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.cfg.Store.EndSession(ctx, id, time.Now(), s.BytesReceived, s.BytesSent); err != nil {
		c.log.Warn("could not record session end", "common_name", s.CommonName, "error", err)
	}
}

// historySessionID returns the store row for a live VPN address.
func (c *Collector) historySessionID(ip netip.Addr) (int64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, ok := c.dbSessions[ip]
	return id, ok
}

// eventLoop drains the ring buffer and turns payloads into names.
func (c *Collector) eventLoop(ctx context.Context) {
	for {
		ev, err := c.dp.ReadEvent()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return
			}
			c.log.Warn("ring buffer read failed", "error", err)
			continue
		}
		c.handleEvent(ev)
	}
}

func (c *Collector) handleEvent(ev ebpfx.Event) {
	cn := c.commonNameFor(ev.ClientIP)

	switch ev.Type {
	case ebpfx.EventConnect:
		host, _, _ := c.cache.Lookup(ev.ClientIP, ev.RemoteIP)
		c.emit(LiveEvent{
			Time: ev.Timestamp, Kind: "new_connection",
			CommonName: cn, ClientIP: ev.ClientIP,
			RemoteIP: ev.RemoteIP, RemotePort: ev.RemotePort,
			Proto: protoName(ev.Proto), Hostname: host,
		})

	case ebpfx.EventDNS:
		obs, err := resolver.ParseDNSResponse(ev.Payload)
		if err != nil || len(obs) == 0 {
			return
		}
		for _, o := range obs {
			c.cache.Observe(ev.ClientIP, o)
		}
		c.emit(LiveEvent{
			Time: ev.Timestamp, Kind: "dns",
			CommonName: cn, ClientIP: ev.ClientIP,
			Hostname: resolver.NormalizeName(obs[0].Name),
			Detail:   fmt.Sprintf("resolved to %s", joinAddrs(obs)),
		})

	case ebpfx.EventSNI:
		name, err := resolver.ParseSNI(ev.Payload)
		if err != nil {
			return
		}
		c.cache.Observe(ev.ClientIP, resolver.Observation{
			IP: ev.RemoteIP, Name: name, Source: resolver.SourceSNI,
		})
		c.emit(LiveEvent{
			Time: ev.Timestamp, Kind: "tls",
			CommonName: cn, ClientIP: ev.ClientIP,
			RemoteIP: ev.RemoteIP, RemotePort: ev.RemotePort,
			Proto: protoName(ev.Proto), Hostname: name,
		})

	case ebpfx.EventHTTP:
		host, err := resolver.ParseHTTPHost(ev.Payload)
		if err != nil {
			return
		}
		c.cache.Observe(ev.ClientIP, resolver.Observation{
			IP: ev.RemoteIP, Name: host, Source: resolver.SourceHTTP,
		})
		c.emit(LiveEvent{
			Time: ev.Timestamp, Kind: "http",
			CommonName: cn, ClientIP: ev.ClientIP,
			RemoteIP: ev.RemoteIP, RemotePort: ev.RemotePort,
			Proto: protoName(ev.Proto), Hostname: host,
		})
	}
}

// scrapeLoop rebuilds the snapshot from the flow map on a fixed cadence.
func (c *Collector) scrapeLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.ScrapeEvery)
	defer ticker.Stop()

	prune := time.NewTicker(time.Minute)
	defer prune.Stop()

	c.rebuild()
	for {
		select {
		case <-ticker.C:
			c.rebuild()
		case <-prune.C:
			if n, err := c.dp.PruneFlows(c.cfg.FlowIdle); err != nil {
				c.log.Warn("pruning flows failed", "error", err)
			} else if n > 0 {
				c.log.Debug("pruned idle flows", "count", n)
			}
			c.cache.Prune()
		case <-ctx.Done():
			return
		}
	}
}

// rebuild assembles a fresh snapshot: kernel counters, joined to management
// identities, labelled with resolved names.
func (c *Collector) rebuild() {
	flows, err := c.dp.Flows()
	if err != nil {
		c.log.Warn("reading flow map failed", "error", err)
		return
	}
	stats, err := c.dp.Stats()
	if err != nil {
		c.log.Warn("reading probe stats failed", "error", err)
	}

	c.mu.RLock()
	sessions := make(map[netip.Addr]mgmt.Session, len(c.sessions))
	for k, v := range c.sessions {
		sessions[k] = v
	}
	mgmtErr := c.snapshot.MgmtError
	healthy := c.snapshot.MgmtHealthy
	c.mu.RUnlock()

	// Fold this scrape's increments into the per-session totals first, so the
	// snapshot below reports accumulated figures rather than whatever the
	// kernel map happens to hold right now.
	c.applyFlowDeltas(flows)

	byClient := make(map[netip.Addr][]Destination)
	var orphans []Destination

	c.mu.RLock()
	for ip, t := range c.totals {
		if _, known := sessions[ip]; !known {
			continue
		}
		dests := make([]Destination, 0, len(t.dests))
		for _, e := range t.dests {
			dests = append(dests, Destination{
				RemoteIP:    e.remoteIP,
				Hostname:    e.hostname,
				NameSource:  e.nameSource,
				Port:        e.port,
				Proto:       protoName(e.proto),
				Service:     serviceName(e.proto, e.port),
				Resource:    c.resourceFor(e.remoteIP),
				TxBytes:     e.tx,
				RxBytes:     e.rx,
				Packets:     e.packets,
				Connections: e.conns,
				FirstSeen:   e.firstSeen,
				LastSeen:    e.lastSeen,
			})
		}
		byClient[ip] = dests
	}
	c.mu.RUnlock()

	// Traffic from addresses the management interface has not claimed is
	// reported straight from the live map; there is no session to accumulate
	// it against.
	for _, f := range flows {
		if _, known := sessions[f.ClientIP]; known {
			continue
		}
		host, src, _ := c.cache.Lookup(f.ClientIP, f.RemoteIP)
		orphans = append(orphans, Destination{
			RemoteIP:    f.RemoteIP,
			Hostname:    host,
			NameSource:  string(src),
			Port:        f.RemotePort,
			Proto:       protoName(f.Proto),
			Service:     serviceName(f.Proto, f.RemotePort),
			TxBytes:     f.TxBytes,
			RxBytes:     f.RxBytes,
			Packets:     f.TxPackets + f.RxPackets,
			Connections: f.Connections,
			FirstSeen:   f.FirstSeen,
			LastSeen:    f.LastSeen,
		})
	}

	now := time.Now()
	views := make([]SessionView, 0, len(sessions))
	for ip, s := range sessions {
		dests := byClient[ip]
		sort.Slice(dests, func(i, j int) bool {
			return dests[i].TxBytes+dests[i].RxBytes >
				dests[j].TxBytes+dests[j].RxBytes
		})

		var tx, rx uint64
		for _, d := range dests {
			tx += d.TxBytes
			rx += d.RxBytes
		}

		txRate, rxRate := c.rateFor(ip, tx, rx, now)

		views = append(views, SessionView{
			CommonName:     s.CommonName,
			Username:       s.Username,
			RealAddress:    s.RealAddr,
			VirtualIP:      ip,
			ClientID:       s.ClientID,
			Cipher:         s.Cipher,
			ConnectedSince: s.ConnectedSince,
			Duration:       time.Since(s.ConnectedSince).Truncate(time.Second).String(),
			TunnelRx:       s.BytesReceived,
			TunnelTx:       s.BytesSent,
			FlowTx:         tx,
			FlowRx:         rx,
			TxRate:         txRate,
			RxRate:         rxRate,
			Destinations:   dests,
		})
	}
	sort.Slice(views, func(i, j int) bool {
		return views[i].CommonName < views[j].CommonName
	})

	sort.Slice(orphans, func(i, j int) bool {
		return orphans[i].TxBytes+orphans[i].RxBytes >
			orphans[j].TxBytes+orphans[j].RxBytes
	})
	if len(orphans) > 50 {
		orphans = orphans[:50]
	}

	c.mu.Lock()
	c.snapshot = Snapshot{
		UpdatedAt:    time.Now(),
		Interface:    c.cfg.Interface,
		VPNSubnet:    c.cfg.VPNSubnet.String(),
		MgmtHealthy:  healthy,
		MgmtError:    mgmtErr,
		Sessions:     views,
		Probe:        stats,
		NamesCached:  c.cache.Len(),
		FlowCount:    len(flows),
		Unattributed: orphans,
	}
	c.mu.Unlock()
}

// applyFlowDeltas turns the kernel's running counters into increments, folds
// them into the per-session totals, and forwards them to the history store.
//
// Called only from scrapeLoop, which is what makes prevFlows safe to touch
// without a lock.
func (c *Collector) applyFlowDeltas(flows []ebpfx.Flow) {
	seen := make(map[flowKey]flowCounters, len(flows))
	batch := make([]store.Destination, 0, len(flows))

	for _, f := range flows {
		c.mu.RLock()
		_, live := c.sessions[f.ClientIP]
		sid, inHistory := c.dbSessions[f.ClientIP]
		c.mu.RUnlock()

		if !live {
			// Traffic from an address the management interface has not told
			// us about yet. Deliberately not recorded in seen, so once the
			// session appears its accumulated bytes arrive as one delta
			// rather than being lost.
			continue
		}

		k := flowKey{
			client: f.ClientIP, remote: f.RemoteIP,
			port: f.RemotePort, proto: f.Proto,
		}
		cur := flowCounters{
			tx: f.TxBytes, rx: f.RxBytes,
			packets:     f.TxPackets + f.RxPackets,
			connections: f.Connections,
		}
		seen[k] = cur

		d := c.prevFlows[k].delta(cur)
		if d.isZero() {
			continue
		}

		host, src, _ := c.cache.Lookup(f.ClientIP, f.RemoteIP)

		c.mu.Lock()
		t, ok := c.totals[f.ClientIP]
		if !ok {
			t = &sessionTotals{dests: make(map[flowKey]*destTotals)}
			c.totals[f.ClientIP] = t
		}
		t.add(k, d, f, host, string(src))
		c.mu.Unlock()

		if c.cfg.Store != nil && inHistory {
			batch = append(batch, store.Destination{
				SessionID:   sid,
				RemoteIP:    f.RemoteIP.String(),
				Port:        f.RemotePort,
				Proto:       protoName(f.Proto),
				Hostname:    host,
				NameSource:  string(src),
				TxBytes:     d.tx,
				RxBytes:     d.rx,
				Packets:     d.packets,
				Connections: d.connections,
				FirstSeen:   f.FirstSeen,
				LastSeen:    f.LastSeen,
			})
		}
	}

	// Replacing the map drops flows the kernel has evicted, so if one of them
	// comes back its counters are treated as new rather than as a decrease.
	c.prevFlows = seen

	if c.cfg.Store != nil {
		c.cfg.Store.RecordDestinations(batch)
	}
}

// rateFor derives bytes per second from the change since the previous scrape.
//
// Called only from rebuild, under no lock of its own: rates is touched
// nowhere else. Counters here are monotonic within a session, so a decrease
// means the session was replaced and the sample is discarded rather than
// producing a negative rate.
func (c *Collector) rateFor(ip netip.Addr, tx, rx uint64, now time.Time) (float64, float64) {
	prev, ok := c.rates[ip]
	c.rates[ip] = rateSample{tx: tx, rx: rx, at: now}

	if !ok {
		return 0, 0
	}
	elapsed := now.Sub(prev.at).Seconds()
	if elapsed <= 0 || tx < prev.tx || rx < prev.rx {
		return 0, 0
	}
	return float64(tx-prev.tx) / elapsed, float64(rx-prev.rx) / elapsed
}

// KillSession disconnects a connected client and records that it happened.
//
// The event goes through the same path as everything else the collector
// observes, so it lands in the activity feed and the audit history alongside
// the connect and disconnect it sits between.
func (c *Collector) KillSession(ctx context.Context, clientID uint32, who string) error {
	c.mgmtMu.Lock()
	client := c.mgmtClient
	c.mgmtMu.Unlock()

	if client == nil {
		return errors.New("management interface is not connected")
	}

	// Resolve the name before the session disappears from the poll.
	var cn string
	var ip netip.Addr
	c.mu.RLock()
	for addr, s := range c.sessions {
		if s.ClientID == clientID {
			cn, ip = s.CommonName, addr
			break
		}
	}
	c.mu.RUnlock()
	if cn == "" {
		return fmt.Errorf("no connected client with id %d", clientID)
	}

	if err := client.KillClient(ctx, clientID); err != nil {
		return err
	}

	c.log.Warn("client disconnected by operator",
		"common_name", cn, "client_id", clientID, "by", who)
	c.emit(LiveEvent{
		Time: time.Now(), Kind: "kill",
		CommonName: cn, ClientIP: ip,
		Detail: "disconnected by " + who,
	})
	return nil
}

// resourceFor asks the enrichment provider what an address is, if one is
// configured. Providers serve this from a cache; it is called once per
// destination on every scrape.
func (c *Collector) resourceFor(addr netip.Addr) *enrich.Resource {
	if c.cfg.Enricher == nil {
		return nil
	}
	if r, ok := c.cfg.Enricher.LookupAddress(addr); ok {
		return &r
	}
	return nil
}

// RecordAdminEvent notes an administrative action in the activity feed and
// the audit history. These have no packet behind them - they are things an
// operator did - but they belong on the same timeline as what they affect.
func (c *Collector) RecordAdminEvent(kind, commonName, detail string) {
	c.emit(LiveEvent{
		Time: time.Now(), Kind: kind,
		CommonName: commonName, Detail: detail,
	})
}

// ------------------------------------------------------------- accessors ---

// Snapshot returns the most recent view.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snapshot
}

// History returns recent live events, newest last.
func (c *Collector) History() []LiveEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]LiveEvent(nil), c.history...)
}

// Subscribe returns a channel of live events and a function to release it.
func (c *Collector) Subscribe() (<-chan LiveEvent, func()) {
	ch := make(chan LiveEvent, 64)

	c.subMu.Lock()
	c.subs[ch] = struct{}{}
	c.subMu.Unlock()

	return ch, func() {
		c.subMu.Lock()
		if _, ok := c.subs[ch]; ok {
			delete(c.subs, ch)
			close(ch)
		}
		c.subMu.Unlock()
	}
}

func (c *Collector) emit(ev LiveEvent) {
	c.mu.Lock()
	c.history = append(c.history, ev)
	if len(c.history) > c.cfg.EventHistory {
		c.history = c.history[len(c.history)-c.cfg.EventHistory:]
	}
	c.mu.Unlock()

	c.persistEvent(ev)

	c.subMu.Lock()
	defer c.subMu.Unlock()
	for ch := range c.subs {
		select {
		case ch <- ev:
		default: // a subscriber that cannot keep up misses events
		}
	}
}

// persistEvent writes an observation to the history store.
//
// TCP SYN events are skipped: a busy client produces them by the thousand and
// they carry nothing the destinations table's connection counter does not
// already hold. What is kept is the record of *identification* - which name a
// user resolved or requested - which is exactly what an audit needs.
func (c *Collector) persistEvent(ev LiveEvent) {
	if c.cfg.Store == nil || ev.Kind == "new_connection" {
		return
	}

	rec := store.Event{
		Time:       ev.Time,
		Kind:       ev.Kind,
		CommonName: ev.CommonName,
		RemotePort: ev.RemotePort,
		Proto:      ev.Proto,
		Hostname:   ev.Hostname,
		Detail:     ev.Detail,
	}
	if ev.ClientIP.IsValid() {
		rec.ClientIP = ev.ClientIP.String()
	}
	if ev.RemoteIP.IsValid() {
		rec.RemoteIP = ev.RemoteIP.String()
	}
	c.cfg.Store.RecordEvent(rec)
}

func (c *Collector) commonNameFor(vpnIP netip.Addr) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if s, ok := c.sessions[vpnIP]; ok {
		return s.CommonName
	}
	return ""
}

func (c *Collector) setMgmtError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.snapshot.MgmtHealthy = true
		c.snapshot.MgmtError = ""
		return
	}
	c.snapshot.MgmtHealthy = false
	c.snapshot.MgmtError = err.Error()
}

// --------------------------------------------------------------- helpers ---

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	default:
		return strconv.Itoa(int(p))
	}
}

var services = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 67: "dhcp", 80: "http", 110: "pop3", 123: "ntp",
	143: "imap", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps",
	995: "pop3s", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
	3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
	6379: "redis", 8080: "http-alt", 8443: "https-alt", 9418: "git",
	27017: "mongodb",
}

func serviceName(proto uint8, port uint16) string {
	if proto == 17 && port == 443 {
		return "quic"
	}
	return services[port]
}

func joinAddrs(obs []resolver.Observation) string {
	if len(obs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(obs))
	for i, o := range obs {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(obs)-3))
			break
		}
		parts = append(parts, o.IP.String())
	}
	return strings.Join(parts, ", ")
}

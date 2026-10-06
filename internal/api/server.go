// Package api serves the dashboard, the JSON API, the live event stream and
// the Prometheus endpoint.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ubuntu/openvpn-monitoring/internal/access"
	"github.com/ubuntu/openvpn-monitoring/internal/collector"
	"github.com/ubuntu/openvpn-monitoring/internal/enrich"
	"github.com/ubuntu/openvpn-monitoring/internal/pki"
	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

//go:embed static
var staticFS embed.FS

// Server exposes a collector over HTTP.
type Server struct {
	col   *collector.Collector
	log   *slog.Logger
	reg   *prometheus.Registry
	store *store.Store

	// pkiPath is the easy-rsa index to read the full user list from. Empty
	// means "look in the usual places on each request", which keeps a PKI that
	// appears after startup from needing a restart.
	pkiPath  string
	serverCN string

	// auth is nil when no credentials are configured, leaving everything open.
	auth *Auth

	// pkiMgr is nil when no writable easy-rsa installation was found, which
	// leaves certificate management unavailable rather than half-working.
	pkiMgr     *pki.Manager
	serverConf string

	// enricher is nil unless an identity source is configured.
	enricher enrich.Provider

	// blocks is nil unless OpenVPN has a client-config-dir to enforce
	// temporary blocks through.
	blocks *access.Manager
}

// WithBlocking enables temporary blocking of users.
func (s *Server) WithBlocking(m *access.Manager) *Server {
	s.blocks = m
	return s
}

// WithEnricher attaches an external identity source.
func (s *Server) WithEnricher(e enrich.Provider) *Server {
	s.enricher = e
	return s
}

// WithCertManager enables issuing and revoking certificates.
func (s *Server) WithCertManager(m *pki.Manager, serverConf string) *Server {
	s.pkiMgr = m
	s.serverConf = serverConf
	return s
}

// WithAuth puts the dashboard and API behind a login.
func (s *Server) WithAuth(a *Auth) *Server {
	s.auth = a
	return s
}

// New wires up the handlers. reg may be nil to skip the metrics endpoint, and
// st may be nil when history is disabled.
func New(col *collector.Collector, reg *prometheus.Registry, st *store.Store, log *slog.Logger) *Server {
	return &Server{col: col, log: log, reg: reg, store: st, serverCN: "server"}
}

// WithPKI points the user list at a specific easy-rsa index, and names the
// certificate belonging to the server itself so it is not listed as a user.
func (s *Server) WithPKI(indexPath, serverCN string) *Server {
	s.pkiPath = indexPath
	if serverCN != "" {
		s.serverCN = serverCN
	}
	return s
}

// pkiIndex resolves the index path, falling back to the conventional
// locations.
func (s *Server) pkiIndex() string {
	if s.pkiPath != "" {
		return s.pkiPath
	}
	return pki.Find()
}

// Handler builds the mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Open: the login exchange itself, whether a login is needed, and the
	// health probe, which a load balancer has to reach without credentials.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/auth", s.handleAuthStatus)
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Everything that exposes traffic data, or changes anything, needs a
	// session.
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/snapshot", s.handleSnapshot)
	protected.HandleFunc("GET /api/sessions", s.handleSessions)
	protected.HandleFunc("GET /api/events", s.handleEvents)
	protected.HandleFunc("GET /api/users", s.handleUsers)
	protected.HandleFunc("PUT /api/users/{common_name}/note", s.handleUserNote)
	protected.HandleFunc("POST /api/sessions/{client_id}/kill", s.handleKillSession)
	protected.HandleFunc("POST /api/certificates", s.handleIssueCert)
	protected.HandleFunc("DELETE /api/certificates/{common_name}", s.handleRevokeCert)
	protected.HandleFunc("GET /api/certificates/{common_name}/profile", s.handleDownloadProfile)
	protected.HandleFunc("GET /api/stream", s.handleStream)
	protected.HandleFunc("GET /api/enrichment", s.handleEnrichment)
	protected.HandleFunc("GET /api/blocks", s.handleBlocks)
	protected.HandleFunc("PUT /api/users/{common_name}/block", s.handleBlockUser)
	protected.HandleFunc("DELETE /api/users/{common_name}/block", s.handleUnblockUser)

	if s.store != nil {
		protected.HandleFunc("GET /api/history/sessions", s.handleHistorySessions)
		protected.HandleFunc("GET /api/history/destinations", s.handleHistoryDestinations)
		protected.HandleFunc("GET /api/history/events", s.handleHistoryEvents)
		protected.HandleFunc("GET /api/history/hosts", s.handleHistoryHosts)
		protected.HandleFunc("GET /api/history/countries", s.handleHistoryCountries)
		protected.HandleFunc("GET /api/history/stats", s.handleHistoryStats)
	}
	mux.Handle("/api/", s.guard(protected))

	if s.reg != nil {
		// Metrics carry the same data, so they are guarded too - but with a
		// bearer token as well, since Prometheus has no browser session.
		mux.Handle("GET /metrics", s.guardMetrics(promhttp.HandlerFor(s.reg,
			promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})))
	}

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		s.log.Error("embedded assets are missing", "error", err)
	} else {
		// The page itself is served unauthenticated; it renders a login form
		// and gets nothing but 401s until a session exists.
		//
		// Registered without a method: "GET /" and "/api/" would otherwise be
		// ambiguous for a GET under /api/, which ServeMux rejects outright.
		// The longer "/api/" pattern wins for those requests either way.
		mux.Handle("/", http.FileServerFS(sub))
	}

	return mux
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.col.Snapshot())
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	snap := s.col.Snapshot()

	// ?common_name=alice narrows to one user.
	if cn := r.URL.Query().Get("common_name"); cn != "" {
		for _, sess := range snap.Sessions {
			if sess.CommonName == cn {
				writeJSON(w, sess)
				return
			}
		}
		http.Error(w, "no such connected client", http.StatusNotFound)
		return
	}
	writeJSON(w, snap.Sessions)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.col.History())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	snap := s.col.Snapshot()
	if !snap.MgmtHealthy {
		http.Error(w, "management interface unreachable: "+snap.MgmtError,
			http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleEnrichment reports the state of the identity source, if any.
//
// Separate from /healthz on purpose: a stale identity source degrades the
// dashboard's labelling, but the VPN monitoring itself is unaffected, so it
// must not make the service look unhealthy to a load balancer.
func (s *Server) handleEnrichment(w http.ResponseWriter, r *http.Request) {
	if s.enricher == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	st := s.enricher.Stats()
	writeJSON(w, struct {
		Enabled bool `json:"enabled"`
		enrich.Stats
	}{true, st})
}

// handleStream pushes live events and periodic snapshots over a WebSocket.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The dashboard is served from this same origin; anything else is
		// someone else's page reading a VPN operator's traffic view.
		InsecureSkipVerify: false,
	})
	if err != nil {
		s.log.Debug("websocket upgrade failed", "error", err)
		return
	}
	defer conn.CloseNow()

	ctx := r.Context()
	events, release := s.col.Subscribe()
	defer release()

	type frame struct {
		Type     string               `json:"type"`
		Event    *collector.LiveEvent `json:"event,omitempty"`
		Snapshot *collector.Snapshot  `json:"snapshot,omitempty"`
	}

	snap := s.col.Snapshot()
	if err := wsjson.Write(ctx, conn, frame{Type: "snapshot", Snapshot: &snap}); err != nil {
		return
	}
	for _, ev := range s.col.History() {
		if err := wsjson.Write(ctx, conn, frame{Type: "event", Event: &ev}); err != nil {
			return
		}
	}

	// Detect a client that has gone away without a close frame.
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := wsjson.Write(ctx, conn, frame{Type: "event", Event: &ev}); err != nil {
				return
			}
		case <-ticker.C:
			snap := s.col.Snapshot()
			if err := wsjson.Write(ctx, conn, frame{Type: "snapshot", Snapshot: &snap}); err != nil {
				return
			}
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "")
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// Serve runs an HTTP server until ctx is cancelled.
func Serve(ctx context.Context, addr string, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("dashboard listening", "addr", addr)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

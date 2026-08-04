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
	"github.com/ubuntu/openvpn-monitoring/internal/collector"
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

	mux.HandleFunc("GET /api/snapshot", s.handleSnapshot)
	mux.HandleFunc("GET /api/sessions", s.handleSessions)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/users", s.handleUsers)
	mux.HandleFunc("GET /api/stream", s.handleStream)
	mux.HandleFunc("GET /healthz", s.handleHealth)

	if s.store != nil {
		mux.HandleFunc("GET /api/history/sessions", s.handleHistorySessions)
		mux.HandleFunc("GET /api/history/destinations", s.handleHistoryDestinations)
		mux.HandleFunc("GET /api/history/events", s.handleHistoryEvents)
		mux.HandleFunc("GET /api/history/hosts", s.handleHistoryHosts)
		mux.HandleFunc("GET /api/history/stats", s.handleHistoryStats)
	}

	if s.reg != nil {
		mux.Handle("GET /metrics", promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{
			ErrorHandling: promhttp.ContinueOnError,
		}))
	}

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		s.log.Error("embedded assets are missing", "error", err)
	} else {
		mux.Handle("GET /", http.FileServerFS(sub))
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

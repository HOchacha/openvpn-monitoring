package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

// parseFilter reads the common query parameters shared by every history
// endpoint.
//
// Times accept RFC3339 ("2026-08-01T00:00:00Z") or a relative offset
// ("-7d", "-24h", "-30m"), because asking "what happened last week" should not
// require formatting a timestamp.
func parseFilter(r *http.Request) (store.Filter, error) {
	q := r.URL.Query()

	f := store.Filter{
		CommonName: q.Get("common_name"),
		Hostname:   strings.ToLower(strings.TrimSpace(q.Get("hostname"))),
		RemoteIP:   q.Get("remote_ip"),
		Kind:       q.Get("kind"),
	}

	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return f, fmt.Errorf("limit must be a number, got %q", v)
		}
		f.Limit = n
	}

	var err error
	if f.From, err = parseTime(q.Get("from")); err != nil {
		return f, fmt.Errorf("from: %w", err)
	}
	if f.To, err = parseTime(q.Get("to")); err != nil {
		return f, fmt.Errorf("to: %w", err)
	}

	// A bare "last N" window is the common case.
	if v := q.Get("since"); v != "" && f.From.IsZero() {
		d, err := parseDuration(v)
		if err != nil {
			return f, fmt.Errorf("since: %w", err)
		}
		f.From = time.Now().Add(-d)
	}

	return f, nil
}

func parseTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if strings.HasPrefix(v, "-") {
		d, err := parseDuration(v[1:])
		if err != nil {
			return time.Time{}, err
		}
		return time.Now().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t, nil
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(secs, 0), nil
	}
	return time.Time{}, fmt.Errorf("want RFC3339, YYYY-MM-DD, a unix time or a relative offset like -7d, got %q", v)
}

// parseDuration extends time.ParseDuration with days and weeks, which is what
// a retention or audit window is actually expressed in.
func parseDuration(v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}
	switch unit := v[len(v)-1]; unit {
	case 'd', 'w':
		n, err := strconv.ParseFloat(v[:len(v)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", v)
		}
		scale := 24 * float64(time.Hour)
		if unit == 'w' {
			scale *= 7
		}
		return time.Duration(n * scale), nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: want something like 30m, 24h, 7d or 2w", v)
	}
	return d, nil
}

func (s *Server) handleHistorySessions(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows, err := s.store.Sessions(r.Context(), f)
	if err != nil {
		s.storeError(w, "sessions", err)
		return
	}
	writeJSON(w, emptyIfNil(rows))
}

func (s *Server) handleHistoryDestinations(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows, err := s.store.Destinations(r.Context(), f)
	if err != nil {
		s.storeError(w, "destinations", err)
		return
	}
	writeJSON(w, emptyIfNil(rows))
}

func (s *Server) handleHistoryEvents(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows, err := s.store.Events(r.Context(), f)
	if err != nil {
		s.storeError(w, "events", err)
		return
	}
	writeJSON(w, emptyIfNil(rows))
}

// handleHistoryHosts is the "who went where" report: destinations aggregated
// across sessions for a time window.
func (s *Server) handleHistoryHosts(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows, err := s.store.TopHosts(r.Context(), f)
	if err != nil {
		s.storeError(w, "hosts", err)
		return
	}
	writeJSON(w, emptyIfNil(rows))
}

func (s *Server) handleHistoryStats(w http.ResponseWriter, r *http.Request) {
	counts, err := s.store.Counts(r.Context())
	if err != nil {
		s.storeError(w, "stats", err)
		return
	}
	writeJSON(w, struct {
		store.Counts
		Backend string      `json:"backend"`
		Writer  store.Stats `json:"writer"`
	}{
		Counts:  counts,
		Backend: string(s.store.Dialect()),
		Writer:  s.store.Stats(),
	})
}

func (s *Server) storeError(w http.ResponseWriter, what string, err error) {
	s.log.Warn("history query failed", "query", what, "error", err)
	http.Error(w, "history query failed: "+err.Error(), http.StatusInternalServerError)
}

// emptyIfNil keeps the JSON an empty array rather than null, which is friendlier
// to every client that iterates the result.
func emptyIfNil[T any](rows []T) []T {
	if rows == nil {
		return []T{}
	}
	return rows
}

package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ubuntu/openvpn-monitoring/internal/collector"
	"github.com/ubuntu/openvpn-monitoring/internal/pki"
	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

// User is one certificate holder, whether or not they are connected.
//
// The management interface only reports who is online, so a client that
// disconnects vanishes from it entirely. Merging three sources gives a list
// that persists: the PKI knows who exists, the history knows who has ever
// connected, and management knows who is connected right now.
type User struct {
	CommonName string `json:"common_name"`
	Online     bool   `json:"online"`

	// From the PKI index, when one is readable.
	CertStatus  string     `json:"cert_status,omitempty"`
	CertExpires *time.Time `json:"cert_expires,omitempty"`

	// Present while connected.
	Session *collector.SessionView `json:"session,omitempty"`

	// From recorded history.
	SessionCount int        `json:"session_count"`
	FirstSeen    *time.Time `json:"first_seen,omitempty"`
	LastSeen     *time.Time `json:"last_seen,omitempty"`
	LastAddress  string     `json:"last_address,omitempty"`
	TotalTx      uint64     `json:"total_tx_bytes"`
	TotalRx      uint64     `json:"total_rx_bytes"`
}

// handleUsers returns every known user, online or not.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	snap := s.col.Snapshot()
	users := map[string]*User{}

	get := func(cn string) *User {
		u, ok := users[cn]
		if !ok {
			u = &User{CommonName: cn}
			users[cn] = u
		}
		return u
	}

	// 1. Everyone the PKI has issued a certificate to, including people who
	//    have never connected and those whose certificate was revoked.
	if path := s.pkiIndex(); path != "" {
		if entries, err := pki.Read(path); err != nil {
			s.log.Debug("could not read PKI index", "path", path, "error", err)
		} else {
			for _, e := range entries {
				// The server's own certificate is not a user.
				if strings.EqualFold(e.CommonName, s.serverCN) {
					continue
				}
				u := get(e.CommonName)
				u.CertStatus = string(e.Status)
				if !e.NotAfter.IsZero() {
					t := e.NotAfter
					u.CertExpires = &t
				}
			}
		}
	}

	// 2. Everyone who has ever connected, with their totals.
	if s.store != nil {
		rows, err := s.store.Users(r.Context(), store.Filter{Limit: 10000})
		if err != nil {
			s.log.Warn("could not read user history", "error", err)
		}
		for _, row := range rows {
			u := get(row.CommonName)
			u.SessionCount = row.Sessions
			u.TotalTx, u.TotalRx = row.TotalTx, row.TotalRx
			u.LastAddress = row.LastAddress
			first, last := row.FirstSeen, row.LastSeen
			u.FirstSeen, u.LastSeen = &first, &last
		}
	}

	// 3. Who is connected at this instant.
	for i := range snap.Sessions {
		sess := snap.Sessions[i]
		u := get(sess.CommonName)
		u.Online = true
		u.Session = &sess
		if u.LastAddress == "" {
			u.LastAddress = sess.RealAddress
		}
	}

	out := make([]User, 0, len(users))
	for _, u := range users {
		out = append(out, *u)
	}

	// Online first, then by most recent activity, then by name so the order is
	// stable when a user has no history at all.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		li, lj := out[i].LastSeen, out[j].LastSeen
		switch {
		case li != nil && lj != nil && !li.Equal(*lj):
			return li.After(*lj)
		case li != nil && lj == nil:
			return true
		case li == nil && lj != nil:
			return false
		}
		return out[i].CommonName < out[j].CommonName
	})

	writeJSON(w, out)
}

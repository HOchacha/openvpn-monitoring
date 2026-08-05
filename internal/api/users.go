package api

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ubuntu/openvpn-monitoring/internal/collector"
	"github.com/ubuntu/openvpn-monitoring/internal/enrich"
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

	// An operator's note about this user.
	Note        string     `json:"note,omitempty"`
	NoteUpdated *time.Time `json:"note_updated_at,omitempty"`

	// Identity is who this is according to an external system, when one is
	// configured and recognises the common name.
	Identity *enrich.Identity `json:"identity,omitempty"`

	// Block is set while the user is barred from connecting. Distinct from a
	// revoked certificate: this one lifts by itself.
	Block *store.Block `json:"block,omitempty"`
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

	// Operator notes attach to users the other sources already know about.
	// A note is not evidence that someone exists - a typo in the common name
	// would otherwise conjure a phantom row and make the list untrustworthy.
	// The note itself is kept, so it appears if that user later shows up.
	if s.store != nil {
		if notes, err := s.store.Notes(r.Context()); err != nil {
			s.log.Warn("could not read user notes", "error", err)
		} else {
			for cn, n := range notes {
				u, known := users[cn]
				if !known {
					continue
				}
				u.Note = n.Note
				t := n.UpdatedAt
				u.NoteUpdated = &t
			}
		}
	}

	// An external identity source, when configured, says who these names are in
	// the system the operator actually administers. Applied last, so it covers
	// users that only the live session list knows about.
	if s.enricher != nil {
		for cn, u := range users {
			if id, ok := s.enricher.LookupUser(cn); ok {
				u.Identity = &id
			}
		}
	}

	// Blocks in force. Like notes, these attach only to users the other
	// sources already know about.
	if s.blocks != nil {
		if active, err := s.blocks.Active(r.Context()); err != nil {
			s.log.Warn("could not read blocks", "error", err)
		} else {
			for cn, b := range active {
				if u, known := users[cn]; known {
					blk := b
					u.Block = &blk
				}
			}
		}
	}

	out := make([]User, 0, len(users))
	for _, u := range users {
		out = append(out, *u)
	}

	// Blocked first, then online, then by most recent activity, then by name
	// so the order is stable when a user has no history at all.
	//
	// A blocked user is offline precisely because they were blocked, so
	// sorting on "online" alone buries the row an operator most wants to see -
	// the administrative state they just put in place, or that is about to
	// expire.
	sort.Slice(out, func(i, j int) bool {
		bi, bj := out[i].Block != nil, out[j].Block != nil
		if bi != bj {
			return bi
		}
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

// handleUserNote stores an operator's note about a user.
//
// Free text against a name, capped and escaped on display, since it is
// operator input that gets rendered back to an operator.
func (s *Server) handleUserNote(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "notes need history enabled (-store)", http.StatusNotImplemented)
		return
	}

	cn := r.PathValue("common_name")
	if cn == "" {
		http.Error(w, "missing common name", http.StatusBadRequest)
		return
	}

	var body struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, "expected {\"note\": \"...\"}", http.StatusBadRequest)
		return
	}

	if err := s.store.SetNote(r.Context(), cn, body.Note); err != nil {
		s.log.Warn("could not save note", "common_name", cn, "error", err)
		http.Error(w, "could not save note", http.StatusInternalServerError)
		return
	}

	s.log.Info("user note updated", "common_name", cn, "cleared", strings.TrimSpace(body.Note) == "")
	w.WriteHeader(http.StatusNoContent)
}

// handleKillSession disconnects a connected client.
//
// This ends a connection; it does not revoke anything. The client's
// certificate is still valid, so a client that retries - the default - will be
// back within seconds. That distinction is stated in the UI too, because
// "disconnect" reads like a stronger action than it is.
func (s *Server) handleKillSession(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("client_id")
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		http.Error(w, "client id must be a number", http.StatusBadRequest)
		return
	}

	who := "an operator"
	if s.auth != nil {
		who = s.auth.user
	}

	if err := s.col.KillSession(r.Context(), uint32(id), who); err != nil {
		s.log.Warn("could not disconnect client",
			"client_id", id, "by", who, "error", err)
		// A client that has already gone is not a server error.
		if strings.Contains(err.Error(), "no connected client") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

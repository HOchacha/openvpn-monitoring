package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

// maxBlock bounds how far ahead a block may be set.
//
// Not a security limit - an operator can always set another one - but a block
// measured in years is a revocation someone typed into the wrong box, and it
// would sit in the directory long after everyone had forgotten about it.
const maxBlock = 365 * 24 * time.Hour

// handleBlockUser bars a user from connecting for a while.
//
//	PUT /api/users/{common_name}/block
//	{"duration": "2h", "reason": "offboarding"}
//
// An omitted or zero duration blocks indefinitely, which still differs from
// revoking: it lifts by deleting a file rather than by regenerating a CRL.
func (s *Server) handleBlockUser(w http.ResponseWriter, r *http.Request) {
	if s.blocks == nil {
		http.Error(w, blockingUnavailable, http.StatusNotImplemented)
		return
	}

	cn := r.PathValue("common_name")
	if cn == "" {
		http.Error(w, "missing common name", http.StatusBadRequest)
		return
	}

	var body struct {
		Duration string `json:"duration"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil && err != io.EOF {
		http.Error(w, `expected {"duration": "2h", "reason": "..."}`, http.StatusBadRequest)
		return
	}

	var until time.Time
	if d := strings.TrimSpace(body.Duration); d != "" && d != "0" {
		parsed, err := time.ParseDuration(d)
		if err != nil {
			http.Error(w, "duration must look like 30m, 2h or 24h", http.StatusBadRequest)
			return
		}
		switch {
		case parsed <= 0:
			http.Error(w, "duration must be positive", http.StatusBadRequest)
			return
		case parsed > maxBlock:
			http.Error(w, "a block longer than a year should be a revocation", http.StatusBadRequest)
			return
		}
		until = time.Now().Add(parsed)
	}

	b, err := s.blocks.Block(r.Context(), cn, until, body.Reason, s.actor())
	if err != nil {
		s.log.Warn("could not block user", "common_name", cn, "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.col.RecordAdminEvent("block", cn, blockDetail(b))
	writeJSON(w, b)
}

// handleUnblockUser lifts a block early.
func (s *Server) handleUnblockUser(w http.ResponseWriter, r *http.Request) {
	if s.blocks == nil {
		http.Error(w, blockingUnavailable, http.StatusNotImplemented)
		return
	}

	cn := r.PathValue("common_name")
	if cn == "" {
		http.Error(w, "missing common name", http.StatusBadRequest)
		return
	}

	if err := s.blocks.Unblock(r.Context(), cn, s.actor()); err != nil {
		s.log.Warn("could not unblock user", "common_name", cn, "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.col.RecordAdminEvent("unblock", cn, "block lifted by "+s.actor())
	w.WriteHeader(http.StatusNoContent)
}

// handleBlocks lists the blocks in force.
func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	if s.blocks == nil {
		writeJSON(w, map[string]any{"enabled": false, "blocks": []store.Block{}})
		return
	}
	active, err := s.blocks.Active(r.Context())
	if err != nil {
		s.log.Warn("could not read blocks", "error", err)
		http.Error(w, "could not read blocks", http.StatusInternalServerError)
		return
	}
	out := make([]store.Block, 0, len(active))
	for _, b := range active {
		out = append(out, b)
	}
	writeJSON(w, map[string]any{
		"enabled": true,
		"dir":     s.blocks.Dir(),
		"blocks":  out,
	})
}

const blockingUnavailable = "temporary blocking needs history (-store) and OpenVPN's " +
	"client-config-dir (-ccd-dir); see the README"

func blockDetail(b store.Block) string {
	var sb strings.Builder
	sb.WriteString("blocked by " + b.CreatedBy)
	if b.Indefinite() {
		sb.WriteString(" until further notice")
	} else {
		sb.WriteString(" until " + b.Until.Format(time.RFC3339))
	}
	if b.Reason != "" {
		sb.WriteString(": " + b.Reason)
	}
	return sb.String()
}

// actor names whoever is making the request, for the audit trail.
func (s *Server) actor() string {
	if s.auth != nil {
		return s.auth.user
	}
	return "an operator"
}

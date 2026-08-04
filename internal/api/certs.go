package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ubuntu/openvpn-monitoring/internal/pki"
)

// certManager returns the PKI manager, or nil when this server has no writable
// easy-rsa installation.
func (s *Server) certManager() *pki.Manager {
	if s.pkiMgr == nil {
		return nil
	}
	return s.pkiMgr
}

// handleIssueCert creates a client certificate.
func (s *Server) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	m := s.certManager()
	if m == nil {
		http.Error(w, "no writable easy-rsa PKI was found; set pki-index", http.StatusNotImplemented)
		return
	}

	var body struct {
		CommonName string `json:"common_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, `expected {"common_name": "..."}`, http.StatusBadRequest)
		return
	}
	if err := pki.ValidateName(body.CommonName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Issuing runs openssl; give it room but do not hang a request forever.
	ctx, cancel := contextWithTimeout(r, 60*time.Second)
	defer cancel()

	if err := m.Issue(ctx, body.CommonName); err != nil {
		s.log.Warn("certificate issue failed",
			"common_name", body.CommonName, "by", s.who(), "error", err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	s.log.Info("certificate issued", "common_name", body.CommonName, "by", s.who())
	s.col.RecordAdminEvent("cert_issue", body.CommonName, "issued by "+s.who())
	w.WriteHeader(http.StatusCreated)
}

// handleRevokeCert revokes a certificate and republishes the CRL.
func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	m := s.certManager()
	if m == nil {
		http.Error(w, "no writable easy-rsa PKI was found; set pki-index", http.StatusNotImplemented)
		return
	}

	cn := r.PathValue("common_name")
	if err := pki.ValidateName(cn); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := contextWithTimeout(r, 60*time.Second)
	defer cancel()

	if err := m.Revoke(ctx, cn); err != nil {
		s.log.Warn("certificate revoke failed",
			"common_name", cn, "by", s.who(), "error", err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	s.log.Warn("certificate revoked", "common_name", cn, "by", s.who())
	s.col.RecordAdminEvent("cert_revoke", cn, "revoked by "+s.who())

	// Revoking does not disconnect anyone already online; the CRL is consulted
	// when a client connects. Say so rather than letting the operator assume.
	resp := struct {
		Revoked     bool   `json:"revoked"`
		CRLEnforced bool   `json:"crl_enforced"`
		StillOnline bool   `json:"still_online"`
		Advice      string `json:"advice,omitempty"`
	}{Revoked: true, CRLEnforced: s.crlEnforced()}

	for _, sess := range s.col.Snapshot().Sessions {
		if sess.CommonName == cn {
			resp.StillOnline = true
			break
		}
	}

	switch {
	case !resp.CRLEnforced:
		resp.Advice = "The server config has no crl-verify line, so this revocation is not enforced. Add 'crl-verify crl.pem' and restart OpenVPN."
	case resp.StillOnline:
		resp.Advice = "Revoked, but the existing connection is unaffected. Disconnect them to apply it now."
	}
	writeJSON(w, resp)
}

// handleDownloadProfile returns a ready-to-use .ovpn.
//
// The file contains the client's private key. Over plain HTTP that key crosses
// the network in the clear, which is worth knowing before this is exposed
// beyond a trusted link.
func (s *Server) handleDownloadProfile(w http.ResponseWriter, r *http.Request) {
	m := s.certManager()
	if m == nil {
		http.Error(w, "no easy-rsa PKI was found; set pki-index", http.StatusNotImplemented)
		return
	}

	cn := r.PathValue("common_name")
	if err := pki.ValidateName(cn); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()

	profile, err := m.Profile(ctx, cn)
	if err != nil {
		s.log.Warn("profile generation failed", "common_name", cn, "error", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	s.log.Info("profile downloaded", "common_name", cn, "by", s.who(), "from", clientIP(r))
	s.col.RecordAdminEvent("profile_download", cn, "downloaded by "+s.who())

	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", cn+".ovpn"))
	// It carries a private key; keep it out of every cache on the way.
	w.Header().Set("Cache-Control", "no-store, private")
	_, _ = io.WriteString(w, profile)
}

// crlEnforced reports whether the running server actually checks the CRL.
func (s *Server) crlEnforced() bool {
	if s.pkiMgr == nil || s.serverConf == "" {
		return false
	}
	return s.pkiMgr.CRLActive(s.serverConf)
}

// who names the operator for audit lines.
func (s *Server) who() string {
	if s.auth != nil {
		return s.auth.user
	}
	return "an operator"
}

// contextWithTimeout bounds a subprocess against the request's lifetime.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

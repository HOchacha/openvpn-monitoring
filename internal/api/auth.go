package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Auth guards the dashboard and API.
//
// It is deliberately small: one operator account, a bcrypt hash in the config
// file, and sessions held in memory. There is no user database because there
// is no multi-user story here - the question this answers is "is this the
// operator", not "which operator".
//
// Sessions live in memory on purpose. Restarting ovpnmon logs everyone out,
// which is the safer failure: a stolen cookie stops working, and nothing
// sensitive outlives the process.
type Auth struct {
	user string
	hash []byte

	// metricsToken lets Prometheus scrape without a browser session. Empty
	// means /metrics needs a normal session like everything else.
	metricsToken string

	// secure marks cookies Secure, which is only correct behind TLS.
	secure bool

	ttl time.Duration

	mu       sync.Mutex
	sessions map[string]time.Time // token -> expiry
}

// AuthConfig configures the guard.
type AuthConfig struct {
	User         string
	PasswordHash string
	MetricsToken string
	Secure       bool
	TTL          time.Duration
}

// NewAuth returns a guard, or nil when no credentials are configured - in
// which case everything stays open, as it was before.
func NewAuth(cfg AuthConfig) (*Auth, error) {
	if cfg.PasswordHash == "" {
		return nil, nil
	}
	if cfg.User == "" {
		cfg.User = "admin"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 12 * time.Hour
	}

	// Fail at startup rather than at the first login attempt.
	if _, err := bcrypt.Cost([]byte(cfg.PasswordHash)); err != nil {
		return nil, errors.New("auth-password-hash is not a bcrypt hash; generate one with 'ovpnmon -hash-password'")
	}

	return &Auth{
		user:         cfg.User,
		hash:         []byte(cfg.PasswordHash),
		metricsToken: cfg.MetricsToken,
		secure:       cfg.Secure,
		ttl:          cfg.TTL,
		sessions:     map[string]time.Time{},
	}, nil
}

const cookieName = "ovpnmon_session"

// HashPassword produces the value for auth-password-hash.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not something to paper over with a weak
		// fallback; refusing to issue a session is the safe response.
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *Auth) issue() string {
	tok := newToken()
	if tok == "" {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// Opportunistically drop expired entries so the map cannot grow forever.
	now := time.Now()
	for t, exp := range a.sessions {
		if exp.Before(now) {
			delete(a.sessions, t)
		}
	}
	a.sessions[tok] = now.Add(a.ttl)
	return tok
}

func (a *Auth) valid(tok string) bool {
	if tok == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	exp, ok := a.sessions[tok]
	if !ok {
		return false
	}
	if exp.Before(time.Now()) {
		delete(a.sessions, tok)
		return false
	}
	return true
}

func (a *Auth) revoke(tok string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, tok)
}

// authenticated reports whether a request carries a live session.
func (a *Auth) authenticated(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return a.valid(c.Value)
}

// metricsAuthorised checks the bearer token Prometheus uses.
func (a *Auth) metricsAuthorised(r *http.Request) bool {
	if a.metricsToken == "" {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.metricsToken)) == 1
}

// setCookie writes the session cookie.
//
// SameSite=Strict is what stops another site from driving the state-changing
// endpoints with the operator's cookie; without a session there was nothing to
// forge, but there is now.
func (a *Auth) setCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

// handleLogin exchanges credentials for a session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication is not configured", http.StatusNotImplemented)
		return
	}

	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}

	userOK := subtle.ConstantTimeCompare([]byte(body.User), []byte(s.auth.user)) == 1
	passOK := bcrypt.CompareHashAndPassword(s.auth.hash, []byte(body.Password)) == nil

	// Compare both regardless of the first result so a wrong username and a
	// wrong password take the same time.
	if !userOK || !passOK {
		s.log.Warn("failed dashboard login",
			"user", body.User, "from", clientIP(r))
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	tok := s.auth.issue()
	if tok == "" {
		http.Error(w, "could not create a session", http.StatusInternalServerError)
		return
	}
	s.auth.setCookie(w, tok, int(s.auth.ttl.Seconds()))
	s.log.Info("dashboard login", "user", body.User, "from", clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout ends the session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if c, err := r.Cookie(cookieName); err == nil {
		s.auth.revoke(c.Value)
	}
	s.auth.setCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

// handleAuthStatus tells the dashboard whether it needs to show a login form.
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, struct {
		Required      bool `json:"required"`
		Authenticated bool `json:"authenticated"`
	}{
		Required:      s.auth != nil,
		Authenticated: s.auth == nil || s.auth.authenticated(r),
	})
}

// guard wraps a handler so it needs a session.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth == nil || s.auth.authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		// The dashboard is a single page that fetches its own data, so an API
		// 401 is what drives it to the login form; redirecting HTML would just
		// hide the reason.
		http.Error(w, "authentication required", http.StatusUnauthorized)
	})
}

// guardMetrics additionally accepts the Prometheus bearer token.
func (s *Server) guardMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case s.auth == nil,
			s.auth.authenticated(r),
			s.auth.metricsAuthorised(r):
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("WWW-Authenticate", `Bearer realm="ovpnmon metrics"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
		}
	})
}

// clientIP is for log lines, not for access decisions.
func clientIP(r *http.Request) string {
	if host, _, ok := strings.Cut(r.RemoteAddr, ":"); ok {
		return host
	}
	return r.RemoteAddr
}

// Package cloudstack answers ovpnmon's enrichment questions from a CloudStack
// management server.
//
// It uses the Apache CloudStack Go SDK rather than a hand-rolled API client.
// Request signing and the response models are CloudStack's business, not
// ovpnmon's - and the SDK's models carry fields a hand-written struct tends to
// miss, secondary NIC addresses among them.
//
// Only read-only list calls are made. Nothing here changes anything in
// CloudStack, and the credentials it needs are correspondingly limited.
package cloudstack

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	csdk "github.com/apache/cloudstack-go/v2/cloudstack"

	"github.com/ubuntu/openvpn-monitoring/internal/enrich"
)

// pageSize bounds one list request.
//
// CloudStack caps an unpaginated reply at its default.page.size (500 out of the
// box), and reports the true total in `count`. Asking for pages explicitly is
// the only way to be sure a large installation is seen whole; without it, VMs
// past the cap silently do not exist as far as ovpnmon is concerned.
const pageSize = 500

// Config points the provider at a management server.
type Config struct {
	// URL is the API endpoint, e.g. http://cloudstack:8080/client/api
	URL string

	APIKey    string
	SecretKey string

	// Timeout bounds a single API call.
	Timeout time.Duration

	// InsecureSkipVerify disables TLS verification, for a management server
	// using a self-signed certificate.
	InsecureSkipVerify bool
}

// Provider implements enrich.Provider against CloudStack.
//
// Every lookup is served from a cache refreshed on a timer. A dashboard render
// asks about every destination on screen, and a round trip to the management
// server per address would make the page unusable - and hammer CloudStack for
// data that changes on the order of minutes.
type Provider struct {
	cs  *csdk.CloudStackClient
	log *slog.Logger

	mu        sync.RWMutex
	byName    map[string]enrich.Identity // alias -> identity
	ambiguous map[string][]string        // alias -> the names it could mean
	userCount int                        // real users, not aliases
	byAddress map[netip.Addr]enrich.Resource
	networks  int
	lastOK    time.Time
	lastErr   string
}

// NewProvider builds a provider. It does not contact the server; call Ping or
// Refresh for that.
func NewProvider(cfg Config, log *slog.Logger) (*Provider, error) {
	if cfg.URL == "" || cfg.APIKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("cloudstack needs url, api key and secret key")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	httpc := &http.Client{Timeout: cfg.Timeout, Transport: tr}

	// verifyssl is inverted relative to InsecureSkipVerify, and is passed on
	// as well as being set on the transport: the SDK builds its own client if
	// none is supplied, and the two must not disagree.
	cs := csdk.NewClient(strings.TrimRight(cfg.URL, "/"),
		cfg.APIKey, cfg.SecretKey, !cfg.InsecureSkipVerify,
		csdk.WithHTTPClient(httpc))

	return &Provider{
		cs:        cs,
		log:       log,
		byName:    map[string]enrich.Identity{},
		ambiguous: map[string][]string{},
		byAddress: map[netip.Addr]enrich.Resource{},
	}, nil
}

// Name implements enrich.Provider.
func (p *Provider) Name() string { return "cloudstack" }

// Ping verifies the endpoint and credentials.
func (p *Provider) Ping(ctx context.Context) error {
	return do(ctx, func() error {
		_, err := p.cs.Configuration.ListCapabilities(
			p.cs.Configuration.NewListCapabilitiesParams())
		return err
	})
}

// do runs a blocking SDK call under a context.
//
// The SDK has no context-aware API; its calls are bounded only by the HTTP
// client's timeout. Waiting on the context here means a shutdown does not have
// to sit through a stalled request. The call itself keeps running until its
// timeout expires - it holds nothing but its own goroutine, and its result is
// discarded.
func do(ctx context.Context, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run refreshes on an interval until ctx is cancelled.
func (p *Provider) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	// Populate immediately so the first dashboard render has data.
	if err := p.Refresh(ctx); err != nil {
		p.log.Warn("initial CloudStack refresh failed", "error", err)
	}

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := p.Refresh(ctx); err != nil {
				p.log.Warn("CloudStack refresh failed", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// Refresh reloads users, VMs and networks.
//
// The whole view is rebuilt and swapped in one go, and a failure leaves the
// previous view untouched. A half-updated cache would report a user as unknown
// for exactly as long as their record happened to be missing, and a cleared one
// would unlabel every user and destination the moment CloudStack hiccuped.
func (p *Provider) Refresh(ctx context.Context) error {
	users, err := p.listUsers(ctx)
	if err != nil {
		p.fail(err)
		return err
	}
	vms, err := p.listVMs(ctx)
	if err != nil {
		p.fail(err)
		return err
	}
	nets, err := p.listNetworks(ctx)
	if err != nil {
		p.fail(err)
		return err
	}
	// A user carries only its domain's leaf name, and two subdomains can share
	// one. The full path is what actually identifies a domain.
	//
	// Not fatal if it cannot be read: a deliberately narrow read-only account -
	// which is what this integration asks for - may not be allowed to list
	// domains, and losing every label over it would be a worse trade than
	// falling back to the leaf name each user already carries.
	domains, err := p.listDomains(ctx)
	if err != nil {
		p.log.Warn("could not list CloudStack domains; qualifying names by their "+
			"leaf domain instead, which cannot tell two subdomains of the same "+
			"name apart", "error", err)
		domains = nil
	}
	pathByDomainID := make(map[string]string, len(domains))
	for _, d := range domains {
		pathByDomainID[d.Id] = strings.Trim(d.Path, "/")
	}

	// Networks grouped by owning account.
	netsByAccount := map[string][]enrich.NetworkRef{}
	for _, n := range nets {
		// Only guest networks belong to a tenant; management, public and
		// storage networks are infrastructure and are nobody's to own.
		if n.Traffictype != "" && !strings.EqualFold(n.Traffictype, "Guest") {
			continue
		}
		netsByAccount[n.Account] = append(netsByAccount[n.Account], enrich.NetworkRef{
			Name: n.Name,
			Type: n.Type,
			CIDR: n.Cidr,
			Zone: n.Zonename,
		})
	}

	vmsByAccount := map[string]int{}
	addrs := make(map[netip.Addr]enrich.Resource, len(vms)*2)
	for _, vm := range vms {
		vmsByAccount[vm.Account]++
		for _, nic := range vm.Nic {
			res := enrich.Resource{
				Source:      "cloudstack",
				Kind:        "vm",
				Name:        vm.Name,
				DisplayName: vm.Displayname,
				Account:     vm.Account,
				Domain:      vm.Domain,
				State:       vm.State,
				Network:     nic.Networkname,
				Zone:        vm.Zonename,
			}
			// Every address the NIC answers on, not just its primary: traffic
			// to a secondary address is traffic to this VM.
			for _, raw := range nicAddresses(nic) {
				if a, err := netip.ParseAddr(raw); err == nil {
					addrs[a] = res
				}
			}
		}
	}

	// The mapping decided for this deployment: a certificate's common name is
	// the CloudStack username. Usernames are unique only within a domain, so
	// each user is registered under several aliases and any alias claimed by
	// two of them is treated as naming neither.
	names := make(map[string]enrich.Identity, len(users))
	claims := make(map[string][]string, len(users)) // alias -> qualified names
	for _, u := range users {
		id := enrich.Identity{
			Source:      "cloudstack",
			Account:     u.Account,
			Domain:      domainOf(pathByDomainID, u),
			DisplayName: strings.TrimSpace(u.Firstname + " " + u.Lastname),
			Email:       u.Email,
			State:       u.State,
			Networks:    netsByAccount[u.Account],
			VMCount:     vmsByAccount[u.Account],
		}
		qualified := id.Domain + "/" + u.Username
		for _, alias := range aliasesFor(u, id.Domain) {
			claims[alias] = appendUnique(claims[alias], qualified)
			names[alias] = id
		}
	}

	// Anything two different users answer to resolves to neither.
	ambiguous := map[string][]string{}
	for alias, owners := range claims {
		if len(owners) < 2 {
			continue
		}
		sort.Strings(owners)
		ambiguous[alias] = owners
		delete(names, alias)
		p.log.Warn("common name matches more than one CloudStack user; it will not resolve",
			"name", alias, "candidates", strings.Join(owners, ", "))
	}

	p.mu.Lock()
	p.byName, p.ambiguous, p.byAddress = names, ambiguous, addrs
	p.userCount, p.networks = len(users), len(nets)
	p.lastOK, p.lastErr = time.Now(), ""
	p.mu.Unlock()

	p.log.Debug("CloudStack view refreshed",
		"users", len(users), "aliases", len(names), "ambiguous", len(ambiguous),
		"addresses", len(addrs), "networks", len(nets))
	return nil
}

// nicAddresses returns every address a NIC holds.
func nicAddresses(nic csdk.Nic) []string {
	out := make([]string, 0, 2+len(nic.Ipaddresses)+len(nic.Secondaryip))
	out = append(out, nic.Ipaddress, nic.Ip6address)
	out = append(out, nic.Ipaddresses...)
	for _, s := range nic.Secondaryip {
		out = append(out, s.Ipaddress)
	}
	return out
}

// ---------------------------------------------------------------- listings ---

func (p *Provider) listUsers(ctx context.Context) ([]*csdk.User, error) {
	var out []*csdk.User
	err := paginate(func(page int) (int, error) {
		q := p.cs.User.NewListUsersParams()
		q.SetListall(true)
		q.SetPagesize(pageSize)
		q.SetPage(page)

		var resp *csdk.ListUsersResponse
		if err := do(ctx, func() (err error) {
			resp, err = p.cs.User.ListUsers(q)
			return
		}); err != nil {
			return 0, fmt.Errorf("listUsers: %w", err)
		}
		out = append(out, resp.Users...)
		return resp.Count, nil
	}, func() int { return len(out) })
	return out, err
}

func (p *Provider) listVMs(ctx context.Context) ([]*csdk.VirtualMachine, error) {
	var out []*csdk.VirtualMachine
	err := paginate(func(page int) (int, error) {
		q := p.cs.VirtualMachine.NewListVirtualMachinesParams()
		q.SetListall(true)
		q.SetPagesize(pageSize)
		q.SetPage(page)

		var resp *csdk.ListVirtualMachinesResponse
		if err := do(ctx, func() (err error) {
			resp, err = p.cs.VirtualMachine.ListVirtualMachines(q)
			return
		}); err != nil {
			return 0, fmt.Errorf("listVirtualMachines: %w", err)
		}
		out = append(out, resp.VirtualMachines...)
		return resp.Count, nil
	}, func() int { return len(out) })
	return out, err
}

func (p *Provider) listDomains(ctx context.Context) ([]*csdk.Domain, error) {
	var out []*csdk.Domain
	err := paginate(func(page int) (int, error) {
		q := p.cs.Domain.NewListDomainsParams()
		q.SetListall(true)
		q.SetPagesize(pageSize)
		q.SetPage(page)

		var resp *csdk.ListDomainsResponse
		if err := do(ctx, func() (err error) {
			resp, err = p.cs.Domain.ListDomains(q)
			return
		}); err != nil {
			return 0, fmt.Errorf("listDomains: %w", err)
		}
		out = append(out, resp.Domains...)
		return resp.Count, nil
	}, func() int { return len(out) })
	return out, err
}

func (p *Provider) listNetworks(ctx context.Context) ([]*csdk.Network, error) {
	var out []*csdk.Network
	err := paginate(func(page int) (int, error) {
		q := p.cs.Network.NewListNetworksParams()
		q.SetListall(true)
		q.SetPagesize(pageSize)
		q.SetPage(page)

		var resp *csdk.ListNetworksResponse
		if err := do(ctx, func() (err error) {
			resp, err = p.cs.Network.ListNetworks(q)
			return
		}); err != nil {
			return 0, fmt.Errorf("listNetworks: %w", err)
		}
		out = append(out, resp.Networks...)
		return resp.Count, nil
	}, func() int { return len(out) })
	return out, err
}

// paginate walks pages until everything the server reports has been collected.
//
// fetch returns the total count the server reports; have reports how many have
// been collected so far. A page that adds nothing ends the walk, so a server
// whose count disagrees with what it actually sends cannot spin here forever.
func paginate(fetch func(page int) (int, error), have func() int) error {
	for page := 1; ; page++ {
		before := have()
		total, err := fetch(page)
		if err != nil {
			return err
		}
		got := have()
		if got >= total || got == before {
			return nil
		}
		// A pathological server could keep returning rows past its own count.
		if page > 1000 {
			return fmt.Errorf("pagination did not terminate after %d pages", page)
		}
	}
}

// ----------------------------------------------------------------- lookups ---

func (p *Provider) fail(err error) {
	p.mu.Lock()
	p.lastErr = err.Error()
	p.mu.Unlock()
}

// LookupUser implements enrich.Provider.
//
// An ambiguous name resolves to an identity that says so, rather than to
// nothing: "this name exists in three domains" and "CloudStack has never heard
// of this name" call for different actions, and the dashboard cannot tell them
// apart from a bare false.
func (p *Provider) LookupUser(commonName string) (enrich.Identity, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if id, ok := p.byName[commonName]; ok {
		return id, true
	}
	if owners, ok := p.ambiguous[commonName]; ok {
		return enrich.Identity{
			Source:     "cloudstack",
			Ambiguous:  true,
			Candidates: append([]string(nil), owners...),
		}, true
	}
	return enrich.Identity{}, false
}

// LookupAddress implements enrich.Provider.
func (p *Provider) LookupAddress(addr netip.Addr) (enrich.Resource, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.byAddress[addr]
	return r, ok
}

// aliasesFor lists every name a certificate may address this user by.
//
// The bare username is the common case. The qualified forms exist so a
// deployment with the same username in two domains can still name them apart;
// "/" cannot appear in a certificate ovpnmon issues, so the separators a
// common name can actually carry are offered too.
func aliasesFor(u *csdk.User, domainPath string) []string {
	bare := []string{u.Username}
	if u.Account != "" && u.Account != u.Username {
		bare = append(bare, u.Account)
	}

	out := append([]string(nil), bare...)
	prefixes := []string{domainPath}
	// The leaf name as well as the full path: ROOT/eng/alice is precise, but
	// nobody names a certificate that.
	if leaf := lastSegment(domainPath); leaf != "" && leaf != domainPath {
		prefixes = append(prefixes, leaf)
	}
	for _, prefix := range prefixes {
		if prefix == "" {
			continue
		}
		for _, name := range bare {
			out = append(out, prefix+"/"+name, prefix+"."+name, prefix+"_"+name)
		}
	}
	return out
}

func lastSegment(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// domainOf prefers the full path, falling back to the leaf name the user
// record carries when the domain listing did not include it.
func domainOf(pathByID map[string]string, u *csdk.User) string {
	if path := pathByID[u.Domainid]; path != "" {
		return path
	}
	return u.Domain
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// Stats implements enrich.Provider.
func (p *Provider) Stats() enrich.Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return enrich.Stats{
		Source:      "cloudstack",
		Healthy:     p.lastErr == "" && !p.lastOK.IsZero(),
		Error:       p.lastErr,
		LastRefresh: p.lastOK,
		Users:       p.userCount,
		Ambiguous:   len(p.ambiguous),
		Addresses:   len(p.byAddress),
		Networks:    p.networks,
	}
}

// Describe is a short line for startup logs.
func (p *Provider) Describe() string {
	s := p.Stats()
	out := fmt.Sprintf("%d users, %d addresses, %d networks", s.Users, s.Addresses, s.Networks)
	if s.Ambiguous > 0 {
		out += fmt.Sprintf(", %d ambiguous names", s.Ambiguous)
	}
	return out
}

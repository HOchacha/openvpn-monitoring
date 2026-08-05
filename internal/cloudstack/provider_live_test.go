package cloudstack

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	csdk "github.com/apache/cloudstack-go/v2/cloudstack"

	"github.com/ubuntu/openvpn-monitoring/internal/enrich"
)

// Integration test against a real management server.
//
// Skipped unless CS_URL, CS_KEY and CS_SECRET are set, so it stays out of the
// way of a normal `go test ./...`. Credentials belong in the environment, never
// in this file:
//
//	CS_URL=http://cloudstack:8080/client/api CS_KEY=... CS_SECRET=... \
//	  go test ./internal/cloudstack -run Live -v
//
// It only reads, and asserts on shape rather than on any particular account, so
// it is safe to point at a live installation.
func liveProvider(t *testing.T) *Provider {
	t.Helper()

	url, key, secret := os.Getenv("CS_URL"), os.Getenv("CS_KEY"), os.Getenv("CS_SECRET")
	if url == "" || key == "" || secret == "" {
		t.Skip("set CS_URL, CS_KEY and CS_SECRET to run the live test")
	}

	p, err := NewProvider(Config{
		URL: url, APIKey: key, SecretKey: secret,
		Timeout:            30 * time.Second,
		InsecureSkipVerify: os.Getenv("CS_INSECURE") == "1",
	}, quietLogger())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func TestLiveRefresh(t *testing.T) {
	p := liveProvider(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := p.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	st := p.Stats()
	t.Logf("view: %s", p.Describe())
	if !st.Healthy {
		t.Errorf("not healthy after a successful refresh: %+v", st)
	}
	if st.Users == 0 {
		t.Error("no users; the credentials may lack visibility beyond their own account")
	}

	// Whatever the server returned has to survive the mapping intact: an
	// address index that resolves to a VM with no name, or an identity with no
	// account, means a field moved in a CloudStack release.
	for addr, r := range p.snapshotAddresses() {
		if !addr.IsValid() {
			t.Errorf("invalid address indexed: %v", addr)
		}
		if r.Name == "" || r.Kind != "vm" {
			t.Errorf("%v mapped to an incomplete resource: %+v", addr, r)
		}
	}
	for cn, id := range p.snapshotUsers() {
		if cn == "" {
			t.Error("a user was indexed under an empty common name")
		}
		if id.Account == "" {
			t.Errorf("%q has no account: %+v", cn, id)
		}
	}
}

// snapshotAddresses and snapshotUsers copy the cache for assertions.
func (p *Provider) snapshotAddresses() map[netip.Addr]enrich.Resource {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[netip.Addr]enrich.Resource, len(p.byAddress))
	for k, v := range p.byAddress {
		out[k] = v
	}
	return out
}

func (p *Provider) snapshotUsers() map[string]enrich.Identity {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]enrich.Identity, len(p.byName))
	for k, v := range p.byName {
		out[k] = v
	}
	return out
}

// TestLiveDump prints what the credentials can actually see.
//
// Not an assertion - a diagnostic for the case where enrichment comes back
// empty. It distinguishes "the API rejected us" from "this installation has
// nothing in it yet", which look identical from the dashboard.
//
//	CS_URL=... CS_KEY=... CS_SECRET=... go test ./internal/cloudstack -run LiveDump -v
func TestLiveDump(t *testing.T) {
	if os.Getenv("CS_URL") == "" {
		t.Skip("set CS_URL, CS_KEY and CS_SECRET to run the live dump")
	}
	cs := csdk.NewClient(os.Getenv("CS_URL"), os.Getenv("CS_KEY"), os.Getenv("CS_SECRET"), false)

	ap := cs.Account.NewListAccountsParams()
	ap.SetListall(true)
	if a, err := cs.Account.ListAccounts(ap); err != nil {
		t.Logf("accounts: ERR %v", err)
	} else {
		t.Logf("accounts: %d", a.Count)
		for _, x := range a.Accounts {
			t.Logf("   %-16s domain=%-8s state=%-8s type=%d users=%d", x.Name, x.Domain, x.State, x.Accounttype, len(x.User))
		}
	}

	up := cs.User.NewListUsersParams()
	up.SetListall(true)
	if u, err := cs.User.ListUsers(up); err == nil {
		for _, x := range u.Users {
			t.Logf("user: %-16s account=%-12s domain=%-8s state=%s", x.Username, x.Account, x.Domain, x.State)
		}
	}

	zp := cs.Zone.NewListZonesParams()
	if z, err := cs.Zone.ListZones(zp); err != nil {
		t.Logf("zones: ERR %v", err)
	} else {
		t.Logf("zones: %d", z.Count)
		for _, x := range z.Zones {
			t.Logf("   %-16s state=%-10s networktype=%s", x.Name, x.Allocationstate, x.Networktype)
		}
	}

	vp := cs.VirtualMachine.NewListVirtualMachinesParams()
	vp.SetListall(true)
	if v, err := cs.VirtualMachine.ListVirtualMachines(vp); err != nil {
		t.Logf("vms: ERR %v", err)
	} else {
		t.Logf("vms: count=%d returned=%d", v.Count, len(v.VirtualMachines))
		for _, x := range v.VirtualMachines {
			t.Logf("   %-16s state=%-10s account=%-12s nics=%d", x.Name, x.State, x.Account, len(x.Nic))
		}
	}

	np := cs.Network.NewListNetworksParams()
	np.SetListall(true)
	if n, err := cs.Network.ListNetworks(np); err != nil {
		t.Logf("networks: ERR %v", err)
	} else {
		t.Logf("networks: count=%d returned=%d", n.Count, len(n.Networks))
		for _, x := range n.Networks {
			t.Logf("   %-16s type=%-10s traffic=%-10s account=%-10s cidr=%s", x.Name, x.Type, x.Traffictype, x.Account, x.Cidr)
		}
	}

	hp := cs.Host.NewListHostsParams()
	if h, err := cs.Host.ListHosts(hp); err != nil {
		t.Logf("hosts: ERR %v", err)
	} else {
		t.Logf("hosts: %d", h.Count)
		for _, x := range h.Hosts {
			t.Logf("   %-16s state=%-10s type=%s", x.Name, x.State, x.Type)
		}
	}
}

package cloudstack

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

const (
	sampleUsers = `{"listusersresponse":{"count":2,"user":[
		{"id":"u-1","username":"alice","account":"alice","domain":"ROOT",
		 "email":"alice@example.com","firstname":"Alice","lastname":"Kim","state":"enabled"},
		{"id":"u-2","username":"bob","account":"bob","domain":"eng","state":"disabled"}]}}`

	sampleVMs = `{"listvirtualmachinesresponse":{"count":3,"virtualmachine":[
		{"id":"vm-1","name":"web-01","displayname":"Web 01","state":"Running",
		 "account":"alice","domain":"ROOT","zonename":"zone1",
		 "nic":[{"networkname":"alice-net","ipaddress":"10.1.1.5",
		         "secondaryip":[{"ipaddress":"10.1.1.55"}]}]},
		{"id":"vm-2","name":"db-01","displayname":"DB 01","state":"Running",
		 "account":"alice","domain":"ROOT","zonename":"zone1",
		 "nic":[{"networkname":"alice-net","ipaddress":"10.1.1.6",
		         "ip6address":"2001:db8::6"}]},
		{"id":"vm-3","name":"bob-01","state":"Stopped","account":"bob","domain":"eng",
		 "zonename":"zone1","nic":[{"networkname":"bob-net","ipaddress":"10.2.2.5"}]}]}}`

	sampleNets = `{"listnetworksresponse":{"count":3,"network":[
		{"id":"n-1","name":"alice-net","type":"Isolated","state":"Implemented",
		 "cidr":"10.1.1.0/24","account":"alice","domain":"ROOT","zonename":"zone1",
		 "traffictype":"Guest"},
		{"id":"n-2","name":"bob-net","type":"Isolated","state":"Implemented",
		 "cidr":"10.2.2.0/24","account":"bob","domain":"eng","zonename":"zone1",
		 "traffictype":"Guest"},
		{"id":"n-3","name":"mgmt","type":"Shared","state":"Setup",
		 "account":"system","traffictype":"Management"}]}}`
)

// fakeCloudStack serves the three list calls a refresh makes.
func fakeCloudStack(t *testing.T, h http.HandlerFunc) *Provider {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	p, err := NewProvider(Config{
		URL: srv.URL + "/client/api", APIKey: "k", SecretKey: "s",
		Timeout: 5 * time.Second,
	}, quietLogger())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func staticHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The SDK signs every request; an unsigned one would mean the
		// credentials never made it into the call.
		if r.URL.Query().Get("signature") == "" {
			t.Error("request was not signed")
		}
		switch r.URL.Query().Get("command") {
		case "listUsers":
			_, _ = w.Write([]byte(sampleUsers))
		case "listVirtualMachines":
			_, _ = w.Write([]byte(sampleVMs))
		case "listNetworks":
			_, _ = w.Write([]byte(sampleNets))
		default:
			http.Error(w, "unexpected command", http.StatusBadRequest)
		}
	}
}

func loadedProvider(t *testing.T) *Provider {
	t.Helper()
	p := fakeCloudStack(t, staticHandler(t))
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return p
}

func TestNewProviderRejectsIncompleteConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no url", Config{APIKey: "k", SecretKey: "s"}},
		{"no key", Config{URL: "http://x/client/api", SecretKey: "s"}},
		{"no secret", Config{URL: "http://x/client/api", APIKey: "k"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewProvider(tc.cfg, quietLogger()); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// The mapping this deployment settled on: an OpenVPN common name is a
// CloudStack username.
func TestLookupUserMapsCommonNameToAccount(t *testing.T) {
	p := loadedProvider(t)

	id, ok := p.LookupUser("alice")
	if !ok {
		t.Fatal("alice was not found")
	}
	if id.Account != "alice" || id.Domain != "ROOT" {
		t.Errorf("account/domain = %q/%q", id.Account, id.Domain)
	}
	if id.DisplayName != "Alice Kim" {
		t.Errorf("display name = %q, want %q", id.DisplayName, "Alice Kim")
	}
	if id.Email != "alice@example.com" {
		t.Errorf("email = %q", id.Email)
	}
	if id.Source != "cloudstack" {
		t.Errorf("source = %q", id.Source)
	}
	if id.VMCount != 2 {
		t.Errorf("VM count = %d, want 2", id.VMCount)
	}
	if len(id.Networks) != 1 || id.Networks[0].Name != "alice-net" {
		t.Fatalf("networks = %+v", id.Networks)
	}
	if id.Networks[0].CIDR != "10.1.1.0/24" || id.Networks[0].Type != "Isolated" {
		t.Errorf("network detail = %+v", id.Networks[0])
	}
}

// A disabled CloudStack user whose VPN certificate is still valid is exactly
// the case an operator wants to see, so the state has to survive the mapping.
func TestLookupUserKeepsDisabledState(t *testing.T) {
	p := loadedProvider(t)

	id, ok := p.LookupUser("bob")
	if !ok {
		t.Fatal("bob was not found")
	}
	if id.State != "disabled" {
		t.Errorf("state = %q, want disabled", id.State)
	}
}

func TestLookupUserUnknownName(t *testing.T) {
	p := loadedProvider(t)
	if _, ok := p.LookupUser("nobody"); ok {
		t.Error("an unknown common name should not resolve")
	}
}

func TestLookupAddressNamesTheVM(t *testing.T) {
	p := loadedProvider(t)

	r, ok := p.LookupAddress(netip.MustParseAddr("10.1.1.5"))
	if !ok {
		t.Fatal("10.1.1.5 was not found")
	}
	if r.Kind != "vm" || r.Name != "web-01" {
		t.Errorf("kind/name = %q/%q", r.Kind, r.Name)
	}
	if r.Account != "alice" || r.Network != "alice-net" || r.State != "Running" {
		t.Errorf("unexpected resource: %+v", r)
	}
}

// Traffic to a NIC's secondary address is traffic to that VM. This is the case
// a hand-written model missed, and the reason the SDK's is used instead.
func TestLookupAddressCoversSecondaryIPs(t *testing.T) {
	p := loadedProvider(t)

	r, ok := p.LookupAddress(netip.MustParseAddr("10.1.1.55"))
	if !ok {
		t.Fatal("the secondary NIC address was not indexed")
	}
	if r.Name != "web-01" {
		t.Errorf("name = %q, want web-01", r.Name)
	}
}

func TestLookupAddressCoversIPv6(t *testing.T) {
	p := loadedProvider(t)

	r, ok := p.LookupAddress(netip.MustParseAddr("2001:db8::6"))
	if !ok {
		t.Fatal("the IPv6 NIC address was not indexed")
	}
	if r.Name != "db-01" {
		t.Errorf("name = %q, want db-01", r.Name)
	}
}

func TestLookupAddressUnknown(t *testing.T) {
	p := loadedProvider(t)
	if _, ok := p.LookupAddress(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("an address outside CloudStack should not resolve")
	}
}

// Management and other infrastructure networks are not a tenant's, so they must
// not appear as networks the user owns.
func TestRefreshIgnoresNonGuestNetworks(t *testing.T) {
	p := loadedProvider(t)

	for _, cn := range []string{"alice", "bob"} {
		id, _ := p.LookupUser(cn)
		for _, n := range id.Networks {
			if n.Name == "mgmt" {
				t.Errorf("%s was given the management network", cn)
			}
		}
	}
}

// CloudStack caps an unpaginated reply at default.page.size and reports the
// real total in `count`. Everything past the first page has to be requested, or
// a large installation is silently seen only in part.
func TestRefreshWalksEveryPage(t *testing.T) {
	const total = 1200 // more than two pages at pageSize=500

	var mu sync.Mutex
	pagesSeen := map[string]int{}

	p := fakeCloudStack(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		cmd := q.Get("command")

		mu.Lock()
		pagesSeen[cmd]++
		page := pagesSeen[cmd]
		mu.Unlock()

		if q.Get("pagesize") == "" || q.Get("page") == "" {
			t.Errorf("%s was requested without pagination", cmd)
		}

		switch cmd {
		case "listUsers":
			var b strings.Builder
			fmt.Fprintf(&b, `{"listusersresponse":{"count":%d,"user":[`, total)
			start := (page - 1) * pageSize
			for i := 0; i < pageSize && start+i < total; i++ {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"id":"u-%d","username":"user%d","account":"acct%d"}`,
					start+i, start+i, start+i)
			}
			b.WriteString(`]}}`)
			_, _ = w.Write([]byte(b.String()))
		case "listVirtualMachines":
			_, _ = w.Write([]byte(`{"listvirtualmachinesresponse":{"count":0}}`))
		case "listNetworks":
			_, _ = w.Write([]byte(`{"listnetworksresponse":{"count":0}}`))
		}
	})

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if st := p.Stats(); st.Users != total {
		t.Errorf("collected %d users, want %d", st.Users, total)
	}
	if _, ok := p.LookupUser("user1199"); !ok {
		t.Error("the user on the last page was not collected")
	}
	if pagesSeen["listUsers"] != 3 {
		t.Errorf("listUsers was fetched %d times, want 3", pagesSeen["listUsers"])
	}
}

// A server whose count disagrees with what it sends must not loop forever.
func TestPaginationStopsOnAnEmptyPage(t *testing.T) {
	p := fakeCloudStack(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("command") {
		case "listUsers":
			// Claims a thousand, sends one, then nothing.
			if r.URL.Query().Get("page") == "1" {
				_, _ = w.Write([]byte(`{"listusersresponse":{"count":1000,
					"user":[{"id":"u-1","username":"alice","account":"alice"}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"listusersresponse":{"count":1000,"user":[]}}`))
		case "listVirtualMachines":
			_, _ = w.Write([]byte(`{"listvirtualmachinesresponse":{"count":0}}`))
		case "listNetworks":
			_, _ = w.Write([]byte(`{"listnetworksresponse":{"count":0}}`))
		}
	})

	done := make(chan error, 1)
	go func() { done <- p.Refresh(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("pagination did not terminate")
	}

	if st := p.Stats(); st.Users != 1 {
		t.Errorf("users = %d, want 1", st.Users)
	}
}

// CloudStack answers 401 with the reason in the body. Losing that text turns a
// wrong secret key into an unexplained failure.
func TestRefreshSurfacesServerError(t *testing.T) {
	p := fakeCloudStack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"listusersresponse":{"errorcode":401,
			"errortext":"unable to verify user credentials"}}`))
	})

	err := p.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "unable to verify user credentials") {
		t.Errorf("error lost the server's message: %v", err)
	}
}

// A failed refresh must leave the previous view intact. Dropping it would make
// every user and destination go unlabelled the moment CloudStack hiccups.
func TestFailedRefreshKeepsPreviousView(t *testing.T) {
	var mu sync.Mutex
	fail := false

	p := fakeCloudStack(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		f := fail
		mu.Unlock()
		if f {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		switch r.URL.Query().Get("command") {
		case "listUsers":
			_, _ = w.Write([]byte(sampleUsers))
		case "listVirtualMachines":
			_, _ = w.Write([]byte(sampleVMs))
		case "listNetworks":
			_, _ = w.Write([]byte(sampleNets))
		}
	})

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}

	mu.Lock()
	fail = true
	mu.Unlock()

	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("expected the second refresh to fail")
	}

	if _, ok := p.LookupUser("alice"); !ok {
		t.Error("alice was lost when a refresh failed")
	}
	if _, ok := p.LookupAddress(netip.MustParseAddr("10.1.1.5")); !ok {
		t.Error("the address index was lost when a refresh failed")
	}
	if st := p.Stats(); st.Healthy || st.Error == "" {
		t.Errorf("stats should report the failure: %+v", st)
	}
}

// The SDK has no context-aware API, so a cancelled context must be honoured by
// the wrapper. Without it, shutdown waits out the HTTP timeout.
func TestRefreshHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	p := fakeCloudStack(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
	})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Refresh(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a cancellation error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Refresh ignored the cancelled context")
	}
}

func TestStatsBeforeFirstRefresh(t *testing.T) {
	p := fakeCloudStack(t, staticHandler(t))

	// Not healthy yet: it holds nothing, and reporting otherwise would claim
	// that an unrecognised name is genuinely unknown to CloudStack.
	if st := p.Stats(); st.Healthy {
		t.Errorf("a provider that has never refreshed is not healthy: %+v", st)
	}
}

func TestStatsCountsTheView(t *testing.T) {
	p := loadedProvider(t)
	st := p.Stats()

	if !st.Healthy {
		t.Errorf("expected healthy: %+v", st)
	}
	if st.Users != 2 {
		t.Errorf("users = %d, want 2", st.Users)
	}
	// Five NIC addresses across three VMs: three primaries, one IPv6, one
	// secondary.
	if st.Addresses != 5 {
		t.Errorf("addresses = %d, want 5", st.Addresses)
	}
	if st.Networks != 3 {
		t.Errorf("networks = %d, want 3", st.Networks)
	}
	if st.LastRefresh.IsZero() {
		t.Error("last refresh was not recorded")
	}
}

// Package enrich defines what an optional identity source can add to what
// ovpnmon observes on its own.
//
// The core knows this interface and nothing else. It does not know about any
// particular system; a provider is registered only when one is configured, and
// when none is, every call site simply sees no extra information. That is what
// keeps "plugin" from meaning "the core grew a dependency". No provider ships
// in this repository - the interface is the extension point for your own.
package enrich

import (
	"context"
	"net/netip"
	"time"
)

// Identity is who a VPN user is, according to an external system.
type Identity struct {
	// Source names the provider, so a dashboard can say where this came from.
	Source string `json:"source"`

	Account     string `json:"account,omitempty"`
	Domain      string `json:"domain,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	State       string `json:"state,omitempty"`

	// Networks the account owns, as human-readable labels.
	Networks []NetworkRef `json:"networks,omitempty"`

	// VMs the account owns.
	VMCount int `json:"vm_count,omitempty"`

	// Ambiguous is set when the common name matches more than one account and
	// the provider refuses to guess which. Every other field is empty in that
	// case; Candidates says what it could have been.
	//
	// Reported rather than silently resolved: picking one would attribute a
	// person's traffic to the wrong tenant, and nothing on screen would say so.
	Ambiguous  bool     `json:"ambiguous,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
}

// NetworkRef is one network belonging to an account.
type NetworkRef struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
	CIDR string `json:"cidr,omitempty"`
	Zone string `json:"zone,omitempty"`
}

// Resource is what a destination address turns out to be.
//
// ovpnmon resolves addresses to hostnames from DNS and TLS; this answers a
// different question - not what an address is called, but what it *is* in the
// infrastructure the operator runs.
type Resource struct {
	Source string `json:"source"`

	Kind        string `json:"kind"` // "vm", "network", ...
	Name        string `json:"name"` // instance name
	DisplayName string `json:"display_name,omitempty"`
	Account     string `json:"account,omitempty"`
	Domain      string `json:"domain,omitempty"`
	State       string `json:"state,omitempty"`
	Network     string `json:"network,omitempty"`
	Zone        string `json:"zone,omitempty"`
}

// Provider supplies identity and resource lookups.
//
// Implementations are expected to serve lookups from a local cache: they are
// called on the dashboard's path and must not make a network round trip per
// destination. Refresh is what goes to the source.
type Provider interface {
	// Name identifies the provider in output and logs.
	Name() string

	// Refresh reloads the provider's view. Called periodically by the caller.
	Refresh(ctx context.Context) error

	// LookupUser maps an OpenVPN common name to an identity. The second
	// return is false when the provider knows nothing about this name.
	LookupUser(commonName string) (Identity, bool)

	// LookupAddress maps a destination address to a resource.
	LookupAddress(addr netip.Addr) (Resource, bool)

	// Stats reports what the provider currently holds, for the health view.
	Stats() Stats
}

// Stats describes a provider's cache.
type Stats struct {
	Source      string    `json:"source"`
	Healthy     bool      `json:"healthy"`
	Error       string    `json:"error,omitempty"`
	LastRefresh time.Time `json:"last_refresh,omitempty"`
	Users       int       `json:"users"`
	Ambiguous   int       `json:"ambiguous,omitempty"`
	Addresses   int       `json:"addresses"`
	Networks    int       `json:"networks"`
}

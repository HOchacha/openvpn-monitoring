// Package ebpfx loads and attaches the ovpnmon dataplane and exposes its maps.
package ebpfx

// The compiled object is embedded in the binary by bpf2go, so deploying
// ovpnmon means shipping one file with no clang or kernel headers on the host.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" ovpnmon ../../bpf/ovpnmon.bpf.c

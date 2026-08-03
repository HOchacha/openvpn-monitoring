// SPDX-License-Identifier: GPL-2.0
//
// ovpnmon dataplane.
//
// Attached to the OpenVPN tun interface with TCX on both directions:
//
//   ingress : VPN client -> internet   (what the user is reaching out to)
//   egress  : internet   -> VPN client (what comes back)
//
// The kernel side does three things and nothing more:
//
//   1. Aggregates every packet into a per-{client, destination} flow entry.
//   2. Emits an event when a new TCP connection starts.
//   3. Snapshots the few payloads that reveal a human-readable destination
//      (DNS replies, TLS SNI, HTTP Host) and ships them to userspace.
//
// Parsing DNS/TLS is deliberately *not* done here. Those payloads are rare
// relative to bulk traffic, and hand-rolling a compression-pointer-aware DNS
// parser that satisfies the verifier buys complexity, not speed. Userspace
// parses them with real libraries instead.
//
// Every path returns TCX_NEXT rather than TCX_PASS. TCX runs the programs
// attached to an interface as a chain and stops at the first one that does not
// return TCX_NEXT, so returning TCX_PASS from a pure observer would silently
// disable every other tc program on the same device - Cilium, a firewall, or a
// second monitoring tool. This program only counts; it never decides a
// packet's fate.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FLOWS     65536
#define MAX_SESSIONS   1024
#define PAYLOAD_SNAP    512
#define MIN_SNAP         12

/* Injected from userspace before load, so the VPN subnet is not baked in. */
const volatile __u32 vpn_net  = 0; /* network address, host byte order */
const volatile __u32 vpn_mask = 0; /* netmask, host byte order         */

/* ------------------------------------------------------------------ types */

struct flow_key {
	__u32 client_ip;   /* VPN-internal address, network byte order */
	__u32 remote_ip;
	__u16 remote_port;
	__u8  proto;
	__u8  _pad;
};

struct flow_stat {
	__u64 tx_bytes;    /* client -> internet */
	__u64 tx_packets;
	__u64 rx_bytes;    /* internet -> client */
	__u64 rx_packets;
	__u64 first_ns;
	__u64 last_ns;
	__u32 connections; /* TCP SYNs seen */
	__u32 client_id;   /* OpenVPN CID, tagged from the session map */
};

struct session_info {
	__u32 client_id;
	__u32 _pad;
};

enum event_type {
	EV_CONNECT = 1,
	EV_DNS     = 2,
	EV_SNI     = 3,
	EV_HTTP    = 4,
};

struct event {
	__u64 ts_ns;
	__u32 client_ip;
	__u32 remote_ip;
	__u32 client_id;
	__u16 remote_port;
	__u16 client_port;
	__u16 payload_len;
	__u8  type;
	__u8  proto;
	__u8  payload[PAYLOAD_SNAP];
};

#define EVENT_HDR_SIZE (__builtin_offsetof(struct event, payload))

/* ------------------------------------------------------------------- maps */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_FLOWS);
	__type(key, struct flow_key);
	__type(value, struct flow_stat);
} flows SEC(".maps");

/* Filled by userspace from the OpenVPN management interface:
 * VPN-internal IP -> OpenVPN client id. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, __u32);
	__type(value, struct session_info);
} sessions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

/* struct event is far too big for the 512-byte BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} scratch SEC(".maps");

/* Counters for observability of the probe itself. */
enum stat_slot {
	ST_PACKETS       = 0,
	ST_NOT_IPV4      = 1,
	ST_NOT_VPN       = 2,
	ST_EVENTS        = 3,
	ST_EVENTS_LOST   = 4,
	ST_TRUNCATED     = 5,
	__ST_MAX         = 6,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, __ST_MAX);
	__type(key, __u32);
	__type(value, __u64);
} probe_stats SEC(".maps");

/* Forces the verifier to observe the bounds we just established, rather than
 * reusing the pre-clamp register. */
#define barrier_var(var) asm volatile("" : "+r"(var))

static __always_inline void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&probe_stats, &slot);
	if (v)
		(*v)++;
}

/* -------------------------------------------------------------- helpers */

static __always_inline int in_vpn_net(__u32 addr_be)
{
	return (bpf_ntohl(addr_be) & vpn_mask) == vpn_net;
}

/* tun devices are L3 (no Ethernet header) but the same program should still
 * work if it is ever attached to a tap/veth. Detect it from the first nibble
 * instead of assuming. Returns the L3 offset, or -1 if this is not IPv4. */
static __always_inline int l3_offset(struct __sk_buff *skb)
{
	__u8 first;

	if (bpf_skb_load_bytes(skb, 0, &first, sizeof(first)) < 0)
		return -1;
	if ((first >> 4) == 4)
		return 0;

	__u16 h_proto;
	if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto,
			       sizeof(h_proto)) < 0)
		return -1;
	if (h_proto != bpf_htons(ETH_P_IP))
		return -1;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &first, sizeof(first)) < 0)
		return -1;
	if ((first >> 4) != 4)
		return -1;

	return ETH_HLEN;
}

static __always_inline __u32 lookup_client_id(__u32 client_ip)
{
	struct session_info *si = bpf_map_lookup_elem(&sessions, &client_ip);

	return si ? si->client_id : 0;
}

static __always_inline void account(struct flow_key *key, __u32 len,
				    int egress, int is_syn, __u32 client_id)
{
	__u64 now = bpf_ktime_get_ns();
	struct flow_stat *st = bpf_map_lookup_elem(&flows, key);

	if (!st) {
		struct flow_stat init = {};

		init.first_ns  = now;
		init.last_ns   = now;
		init.client_id = client_id;
		if (egress) {
			init.rx_bytes   = len;
			init.rx_packets = 1;
		} else {
			init.tx_bytes   = len;
			init.tx_packets = 1;
			init.connections = is_syn ? 1 : 0;
		}
		bpf_map_update_elem(&flows, key, &init, BPF_ANY);
		return;
	}

	if (egress) {
		__sync_fetch_and_add(&st->rx_bytes, len);
		__sync_fetch_and_add(&st->rx_packets, 1);
	} else {
		__sync_fetch_and_add(&st->tx_bytes, len);
		__sync_fetch_and_add(&st->tx_packets, 1);
		if (is_syn)
			__sync_fetch_and_add(&st->connections, 1);
	}
	st->last_ns = now;
	if (client_id && !st->client_id)
		st->client_id = client_id;
}

/* Copy up to PAYLOAD_SNAP bytes of L4 payload into a ring buffer event. */
static __always_inline void emit_payload(struct __sk_buff *skb, __u8 type,
					 __u32 payload_off, struct flow_key *key,
					 __u16 client_port, __u32 client_id)
{
	__u32 zero = 0;
	struct event *ev = bpf_map_lookup_elem(&scratch, &zero);

	if (!ev)
		return;

	__u32 skb_len = skb->len;

	if (payload_off >= skb_len)
		return;

	__u32 avail = skb_len - payload_off;

	if (avail > PAYLOAD_SNAP) {
		avail = PAYLOAD_SNAP;
		bump(ST_TRUNCATED);
	}
	/* The barrier has to come first: without it the compiler knows the
	 * clamp already bounded avail, drops the mask as dead code, and passes
	 * the original register - which the verifier still sees as possibly
	 * negative after the 32-bit subtraction - to the helper. Masking after
	 * the barrier survives optimisation and bounds the very register that
	 * is handed to bpf_skb_load_bytes. */
	barrier_var(avail);
	avail &= 0x3ff;
	if (avail > PAYLOAD_SNAP || avail < MIN_SNAP)
		return;

	if (bpf_skb_load_bytes(skb, payload_off, ev->payload, avail) < 0)
		return;

	ev->ts_ns       = bpf_ktime_get_ns();
	ev->client_ip   = key->client_ip;
	ev->remote_ip   = key->remote_ip;
	ev->client_id   = client_id;
	ev->remote_port = key->remote_port;
	ev->client_port = client_port;
	ev->payload_len = (__u16)avail;
	ev->type        = type;
	ev->proto       = key->proto;

	if (bpf_ringbuf_output(&events, ev, EVENT_HDR_SIZE + avail, 0) < 0)
		bump(ST_EVENTS_LOST);
	else
		bump(ST_EVENTS);
}

static __always_inline void emit_connect(struct flow_key *key, __u16 client_port,
					 __u32 client_id)
{
	__u32 zero = 0;
	struct event *ev = bpf_map_lookup_elem(&scratch, &zero);

	if (!ev)
		return;

	ev->ts_ns       = bpf_ktime_get_ns();
	ev->client_ip   = key->client_ip;
	ev->remote_ip   = key->remote_ip;
	ev->client_id   = client_id;
	ev->remote_port = key->remote_port;
	ev->client_port = client_port;
	ev->payload_len = 0;
	ev->type        = EV_CONNECT;
	ev->proto       = key->proto;

	if (bpf_ringbuf_output(&events, ev, EVENT_HDR_SIZE, 0) < 0)
		bump(ST_EVENTS_LOST);
	else
		bump(ST_EVENTS);
}

/* ---------------------------------------------------------------- core */

static __always_inline int handle(struct __sk_buff *skb, int egress)
{
	bump(ST_PACKETS);

	int off = l3_offset(skb);

	if (off < 0) {
		bump(ST_NOT_IPV4);
		return TCX_NEXT;
	}

	struct iphdr iph;

	if (bpf_skb_load_bytes(skb, off, &iph, sizeof(iph)) < 0)
		return TCX_NEXT;

	__u32 ihl = iph.ihl * 4;

	if (ihl < sizeof(struct iphdr))
		return TCX_NEXT;

	struct flow_key key = {};
	__u16 client_port = 0;

	/* On ingress the client is the source; on egress it is the destination.
	 * Anything that is not a VPN client on the expected side is not ours. */
	if (egress) {
		if (!in_vpn_net(iph.daddr)) {
			bump(ST_NOT_VPN);
			return TCX_NEXT;
		}
		key.client_ip = iph.daddr;
		key.remote_ip = iph.saddr;
	} else {
		if (!in_vpn_net(iph.saddr)) {
			bump(ST_NOT_VPN);
			return TCX_NEXT;
		}
		key.client_ip = iph.saddr;
		key.remote_ip = iph.daddr;
	}
	key.proto = iph.protocol;

	__u32 l4_off = off + ihl;
	__u32 payload_off = 0;
	int is_syn = 0;
	int is_frag = (iph.frag_off & bpf_htons(0x1fff)) != 0;

	if (iph.protocol == IPPROTO_TCP && !is_frag) {
		struct tcphdr th;

		if (bpf_skb_load_bytes(skb, l4_off, &th, sizeof(th)) < 0)
			return TCX_NEXT;

		key.remote_port = bpf_ntohs(egress ? th.source : th.dest);
		client_port     = bpf_ntohs(egress ? th.dest : th.source);
		payload_off     = l4_off + th.doff * 4;
		is_syn          = th.syn && !th.ack;
	} else if (iph.protocol == IPPROTO_UDP && !is_frag) {
		struct udphdr uh;

		if (bpf_skb_load_bytes(skb, l4_off, &uh, sizeof(uh)) < 0)
			return TCX_NEXT;

		key.remote_port = bpf_ntohs(egress ? uh.source : uh.dest);
		client_port     = bpf_ntohs(egress ? uh.dest : uh.source);
		payload_off     = l4_off + sizeof(struct udphdr);
	}

	__u32 client_id = lookup_client_id(key.client_ip);

	account(&key, skb->len, egress, is_syn, client_id);

	if (is_frag)
		return TCX_NEXT;

	/* Identify the destination in human terms, cheaply. */
	if (egress) {
		/* DNS replies name the addresses everything else will use. */
		if (iph.protocol == IPPROTO_UDP && key.remote_port == 53)
			emit_payload(skb, EV_DNS, payload_off, &key,
				     client_port, client_id);
	} else {
		if (is_syn)
			emit_connect(&key, client_port, client_id);

		if (iph.protocol == IPPROTO_TCP && payload_off < skb->len) {
			__u8 probe[6];

			if (bpf_skb_load_bytes(skb, payload_off, probe,
					       sizeof(probe)) == 0) {
				/* TLS handshake record carrying a ClientHello. */
				if (key.remote_port == 443 && probe[0] == 0x16 &&
				    probe[5] == 0x01)
					emit_payload(skb, EV_SNI, payload_off,
						     &key, client_port, client_id);
				/* Plaintext HTTP request; the Host header names it. */
				else if (key.remote_port == 80 &&
					 (probe[0] == 'G' || probe[0] == 'P' ||
					  probe[0] == 'H' || probe[0] == 'D' ||
					  probe[0] == 'O' || probe[0] == 'C'))
					emit_payload(skb, EV_HTTP, payload_off,
						     &key, client_port, client_id);
			}
		}
		/* DNS queries over TCP/53 are rare enough to ignore; the reply
		 * on the egress path is captured for UDP, which is what
		 * resolvers actually use here. */
	}

	return TCX_NEXT;
}

SEC("tc/ingress")
int ovpnmon_ingress(struct __sk_buff *skb)
{
	return handle(skb, 0);
}

SEC("tc/egress")
int ovpnmon_egress(struct __sk_buff *skb)
{
	return handle(skb, 1);
}

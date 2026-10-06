# eBPF probe performance

This is a design note on what the probe costs per packet and where the room to
make it cheaper is.

Optimizations **A** and **B** below are **implemented** in `bpf/ovpnmon.bpf.c`:
the header parsing uses direct packet access, and the per-packet session lookup
is gone from the bulk path. The rewrite passes the kernel verifier (the
`internal/ebpfx` load test attaches it). The byte counts are unchanged and
exact — nothing is sampled. What remains open is a throughput measurement on a
live VPN and the optional event-path sampling discussed at the end.

For how to measure, see `dev/incast-bench.sh`.

## Where the cost is

The probe is attached with TCX on the tun device, ingress and egress, and runs
on **every packet** the VPN carries. The architecture is already the right shape
for this: aggregation happens **in the kernel** in the `flows` LRU map, and only
the rare payloads that name a destination (DNS replies, TLS ClientHello, the
first HTTP request) are shipped to userspace. So the lever is not "do more in
the kernel" — that is already done — it is the fixed per-packet cost on the bulk
data path.

Per packet, `handle()` currently does:

| Step | Cost |
|---|---|
| `bump(ST_PACKETS)` | per-CPU array lookup + increment |
| `l3_offset()` | 1 `bpf_skb_load_bytes` (1 byte) — helper call |
| `bpf_skb_load_bytes(iph, 20)` | helper call + 20-byte copy |
| `in_vpn_net()` | arithmetic, cheap |
| `bpf_skb_load_bytes(l4hdr)` | helper call + 8–20 byte copy (TCP/UDP) |
| `lookup_client_id()` | `sessions` hash lookup — **every packet** |
| `account()` | `flows` LRU lookup + atomic adds — **every packet** |

For a client pulling a large file, every data packet pays all of this. The two
`bpf_skb_load_bytes` helper calls and the `sessions` hash lookup are the parts
that can go away without changing what the tool reports.

## Implemented optimizations (accuracy-preserving)

### A. Direct packet access instead of `bpf_skb_load_bytes` — done

`bpf_skb_load_bytes` is a helper call that copies bytes into a stack buffer. For
the header region — the IP header and the TCP/UDP header — the same bytes are now
read directly from `skb->data`, bounds-checked against `skb->data_end`, with no
helper call and no copy. This is the standard way to make a tc/TCX program fast
and is the single biggest win here.

Shape:

```c
void *data     = (void *)(long)skb->data;
void *data_end = (void *)(long)skb->data_end;
struct iphdr *iph = data + off;
if ((void *)(iph + 1) > data_end)
    return TCX_NEXT;              /* verifier-checked bound */
/* read iph->saddr, iph->daddr, iph->protocol, iph->ihl directly */
```

Notes and caveats:

- The headers are almost always in the linear region, so direct access
  succeeds. If a header ever straddles the non-linear boundary the bound check
  fails and the packet is skipped for naming — acceptable, and it can be made
  exact with a one-time `bpf_skb_pull_data(skb, hdr_len)` if measurement shows it
  matters.
- **Keep `bpf_skb_load_bytes` for the payload snapshot** (`emit_payload`). That
  copy can reach 512 bytes into data that may be non-linear, and the helper
  handles that correctly. The payload path is rare, so it is not the bottleneck.
- `iph->ihl * 4` still needs its lower bound checked (`>= sizeof(struct iphdr)`)
  before it is used as an offset, exactly as today.

### B. Skip the `sessions` lookup for established flows — done

`client_id` (the OpenVPN CID) does not change for the life of a flow. It used to
be looked up on every packet; now `account()` fetches it lazily and returns it,
so the lookup runs **only when it is actually needed**:

- flow miss (new `flow_stat`): look up and tag, as today;
- flow hit with `st->client_id == 0` (session map was not yet populated when the
  flow started): look up and back-fill;
- flow hit with a non-zero `client_id`: **skip the lookup entirely**.

On the dominant bulk-traffic path every packet is the third case, so this
removes a hash lookup per packet. Correctness is unchanged: the id a flow gets is
the same, just fetched once instead of every packet.

### Minor

- `bump(ST_PACKETS)` is a per-CPU op and cheap; leave it for observability.
- The stat bumps could be batched into a single per-CPU struct update, but the
  gain is small next to A and B.

## Why not sample bytes

Sampling the **accounting** path — counting only 1 in N packets and scaling — is
tempting for raw throughput but wrong for this tool. The dashboard and the
`openvpn_*_bytes` metrics report actual per-destination byte counts that
operators read as truth; scaled estimates would make those counts wrong, and the
error is largest exactly for the small flows (a handful of packets) that name
where a user went. The expensive-but-exact aggregation is the point.

Sampling the **event** path (connect notifications, payload snapshots) is
defensible under extreme connection rates, because those only affect how many
destinations get a human-readable name, not the byte totals. But those paths are
already conditional and rare relative to bulk traffic, so the win is small and it
trades away naming coverage. Prefer A and B first; reach for event sampling only
if a benchmark shows the event path is actually hot.

## Validating a change

Any edit to `bpf/ovpnmon.bpf.c` must:

1. recompile and regenerate the embedded object and Go bindings: `make generate`
   (needs clang 15+ and `libbpf-dev`);
2. pass the kernel verifier — `internal/ebpfx` loads the program in a test, so
   `make test-root` exercises it;
3. be measured with `dev/incast-bench.sh` before and after, watching per-packet
   cost, `probe_events_lost`, and that attribution stays correct.

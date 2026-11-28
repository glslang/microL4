# M9 red team: `net` answers pings and datagrams from martian sources

**Severity:** low. `net` sends nothing larger than what it received, and
only one frame for each, but it answers sources that RFC 1122 says a host
must drop without a word, and its replies go out through the gateway with
a destination no router should forward: loopback, "this network" and the
reserved class E. It also answers their ARP requests and caches them.

**Where:** `user/net/src/stack.rs`, `Stack::is_peer`, which `Stack::arp`
(the sender) and `Stack::ipv4` (the source) both use; `docs/design.md`,
"`net`", the ARP and IPv4 rows of the layer table.

**Status:** fixed in the M9 fix round: a shared `Ip::is_unicast` (not in `0.0.0.0/8` or `127.0.0.0/8`, nor from `224.0.0.0` up) that both the stack's peer check and `Config::new` use; the test `martian_sources_are_never_answered` passes and stays, with three new goldens, `echo/refuses_a_{loopback,this_network,reserved}_source`. Found by the M9 red team at `3e22091`.

## What breaks

`is_peer` refuses `0.0.0.0`, `255.255.255.255`, `224.0.0.0/4`, the stack's
own address and its subnet's broadcast, as the design's table lists. It
takes every other address as a peer, so a packet from any of these is
answered:

| Source | Why it must be dropped |
| --- | --- |
| `127.0.0.0/8` | loopback: "MUST NOT appear outside a host" (RFC 1122, 3.2.1.3 (g)) |
| `0.0.0.0/8` with a non-zero host | "this host on this network", legal only as a source during start-up, and then only for `0.0.0.0` itself (3.2.1.3 (a), (b)) |
| `240.0.0.0/4` | class E, reserved (3.2.1.3 (c); RFC 1112, 4) |

3.2.1.3 ends: "A host MUST silently discard an incoming datagram
containing an IP source address that is invalid by the rules of this
section." The stack's own configuration agrees with the RFC about these
addresses: `Config::parse` refuses each as `net`'s address, as not
unicast ("not in `0.0.0.0/8` or `127.0.0.0/8`, nor from `224.0.0.0` up").
Only the stack's check of its peers forgot them. The proptests do not
notice, because their own `is_peer` copies the stack's.

What `net` does with, say, an echo request from `127.0.0.1`: the next
hop is the gateway (the source is off the subnet), whose MAC it has, so it
sends at once an echo reply from `10.0.2.15` to `127.0.0.1` in a frame to
the gateway. A UDP datagram to port 7 is echoed the same way. An ARP
request for `10.0.2.15` from sender `127.0.0.1` is answered, and
`127.0.0.1` takes an entry of the eight in the cache.

The harm is small: each answer is one frame, no larger than the request,
to the gateway's MAC; a router drops it (Linux and FreeBSD drop martian
destinations), and the cache entry can only evict an older one, which
any spoofed ARP request already can. But it is a datagram answered that
should not be, which the brief's first guarantee rules out, and with a
source the stack itself calls not unicast.

## The test

`martian_sources_are_never_answered` in `user/net/src/tests/redteam.rs`,
`#[ignore]`d. For each of `127.0.0.1`, `127.1.2.3`, `0.1.2.3`,
`240.0.0.1` and `255.255.255.254` it brings a stack up with its gateway
resolved, feeds it an echo request and a datagram to port 7 from that
source, then an ARP request for its address from that sender, and
asserts nothing is answered and nothing cached. It fails at `3e22091`
with every source answered both ways and learnt:

```
10 packets sent to martian sources (source, destination, protocol):
[([127, 0, 0, 1], [127, 0, 0, 1], 1), ([127, 0, 0, 1], [127, 0, 0, 1], 17), ...];
ARP requests from martian senders (sender, answered, cached):
[([127, 0, 0, 1], true, true), ([127, 1, 2, 3], true, true), ...]
```

(the line wrapped here), an echo reply and a datagram for each of the
five, and an ARP reply and a cache entry for each.

`cargo test -p net --lib redteam -- --ignored` runs it.

**How sure:** certain that the stack answers; the RFC's rule is a MUST.
Whether M9 wants it is the design's call: the layer table lists exactly
the addresses the stack refuses, so the behaviour matches the note, and
the finding is against RFC 1122 and the stack's own notion of unicast,
not against the table.

## Proposed fix

Refuse in `is_peer` what `Config::parse` refuses as an address: `0/8`
(not only `0.0.0.0`), `127/8`, and everything from `224.0.0.0` up (so
class E with multicast, and `255.255.255.255` with them), counted as
today (`ip_bad_source`, `arp_bad_sender`). One function can serve both,
`Ip::is_unicast`, so that the two cannot drift again. Add golden cases
`ipv4/from_loopback`, `ipv4/from_this_network`, `ipv4/from_class_e` and
`arp/sender_loopback`, add the three ranges to `tests/props.rs`'s
`ADDRS`, and write its `is_peer` from the RFC rather than from the
stack, then un-ignore the test. The design's IPv4 and ARP rows should
name the ranges.

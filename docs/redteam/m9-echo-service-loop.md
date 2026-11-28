# M9 red team: one spoofed datagram starts an endless echo-chargen loop

**Severity:** low. It needs a host on the path that runs one of the UDP
small services (chargen, daytime, qotd, time) and answers datagrams from
port 7, which few do today; but then one spoofed datagram, from anyone
who can reach `net`, makes `net` and that host exchange datagrams for
ever, with nobody sending again. Each echo is no larger than its request
and goes to the request's source, so it is a loop, not an amplifier.

**Where:** `user/net/src/stack.rs`, `Stack::udp` (`d.src_port == 0 ||
d.src_port == S::PORT` is the only port check); `docs/design.md`, "`net`",
the UDP row ("to port 7 from source port 0 or 7 ... refused").

**Status:** open. Found by the M9 red team at `3e22091`.

## What breaks

The stack refuses a datagram to port 7 from port 7, so two echo services
cannot answer each other. The classic loop is the other one: echo with
chargen (CVE-1999-0103; CERT CA-1996-01, "UDP Port Denial-of-Service
Attack"). chargen (port 19, RFC 864) answers every datagram, whatever it
holds, with a line of 0 to 512 bytes to the datagram's source port, and
daytime (13), qotd (17) and time (37) answer the same way with a line or
a word. So an attacker sends one datagram to `10.0.2.15:7` with the
source `victim:19` forged; `net` echoes it to `victim:19`, from port 7;
chargen answers to `10.0.2.15:7` from 19; `net` echoes that; and so on,
each turn one frame each way, until a datagram is lost. The stack has no
timer and no per-peer limit, so it never stops by itself.

FreeBSD's inetd refuses a datagram whose source port is that of any of
its own built-in UDP services (`check_loop` in `usr.sbin/inetd`, from
memory), which covers chargen and daytime when it runs them too; `net`
runs only echo, so its port check is inetd's for that configuration, and
the gap is the peer's chargen, which `net` cannot see.

## The test

`one_spoofed_datagram_cannot_start_an_endless_loop` in
`user/net/src/tests/redteam.rs`, `#[ignore]`d. It brings a stack up,
resolves a peer `10.0.2.3`, feeds one datagram from `10.0.2.3:19` to port
7, then plays chargen: each echo the stack sends to port 19 is answered
with a 72-byte line from port 19 to port 7, up to 1,000 turns. It asserts
the stack echoes at most once, and fails at `3e22091`:

```
the stack echoed 1000 times to [10, 0, 2, 3]'s chargen port from one spoofed datagram (1000 datagrams echoed)
```

`cargo test -p net --lib redteam -- --ignored` runs it.

**How sure:** certain of the loop against a chargen that answers port 7;
how many such hosts M9's networks hold is the open part, hence low.

## Proposed fix

Refuse to port 7 the source ports of the UDP small services an echo can
loop with, as well as 0 and 7: 13 (daytime), 17 (qotd), 19 (chargen) and
37 (time), counted in `udp_refused`; or, more simply and as some stacks
do, every source port below 1024 but none of the ephemeral range, since a
client of echo sends from an ephemeral port. Either is one line in
`Stack::udp` and one in the UDP row of the design's table; add golden
cases `echo/from_chargen` and `echo/from_daytime`, extend
`tests/props.rs`'s datagram oracle with the refused ports, and un-ignore
the test.

"""Frame builders, the goldens' layout, and a case writer for net's goldens.

Independent of the Rust code: its own checksum, its own builders. Every
expected frame is written here from the design's rules.
"""
import os

US = bytes([10, 0, 2, 15])
GW = bytes([10, 0, 2, 2])
MAC = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
GWMAC = bytes([0x52, 0x55, 0x0A, 0x00, 0x02, 0x02])
BC = b"\xff" * 6
ZERO = b"\x00" * 6
BCAST = bytes([255, 255, 255, 255])

NAMES = """frames_in frames_out arp_answered arp_sent arp_learnt icmp_answered
ping_sent icmp_replies udp_received udp_echoed eth_short eth_long eth_not_ours
eth_type arp_malformed arp_bad_sender arp_not_ours ip_malformed ip_checksum
ip_fragment ip_not_ours ip_bad_source ip_protocol icmp_short icmp_checksum
icmp_broadcast icmp_other udp_length udp_checksum udp_port udp_refused tx_full
held_replaced held_full held_evicted""".split()


def ip(s):
    return bytes(int(x) for x in s.split("."))


def host(n):
    """10.0.2.n and its MAC 02:00:00:00:00:n."""
    return bytes([10, 0, 2, n]), bytes([2, 0, 0, 0, 0, n])


def ones_sum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = data[i] << 8 | (data[i + 1] if i + 1 < len(data) else 0)
        s += w
        s = (s & 0xFFFF) + (s >> 16)
    return s


def csum(data):
    return ~ones_sum(data) & 0xFFFF


def u16(v):
    return bytes([(v >> 8) & 0xFF, v & 0xFF])


def eth(dst, src, ty, payload):
    return bytes(dst) + bytes(src) + u16(ty) + bytes(payload)


def arp(op, sha, spa, tha, tpa, htype=1, ptype=0x0800, hlen=6, plen=4):
    return u16(htype) + u16(ptype) + bytes([hlen, plen]) + u16(op) + sha + spa + tha + tpa


def ipv4(src, dst, proto, payload, ident=0x1234, flags=0x4000, ttl=64, tos=0,
         options=b"", total=None, ihl=None, version=4, check=None):
    hl = 20 + len(options)
    if ihl is None:
        ihl = hl // 4
    if total is None:
        total = hl + len(payload)
    h = bytearray([version << 4 | ihl, tos]) + u16(total) + u16(ident) + u16(flags) \
        + bytes([ttl, proto]) + b"\0\0" + src + dst + options
    c = csum(bytes(h)) if check is None else check
    h[10:12] = u16(c)
    return bytes(h) + bytes(payload)


def udp(src, dst, sport, dport, payload, checksum=True, length=None, check=None,
        pseudo_dst=None):
    ln = 8 + len(payload) if length is None else length
    d = bytearray(u16(sport) + u16(dport) + u16(ln) + b"\0\0" + bytes(payload))
    if check is not None:
        d[6:8] = u16(check)
    elif checksum:
        d[6:8] = u16(udp_sum(src, pseudo_dst or dst, bytes(d)))
    return bytes(d)


def udp_sum(src, dst, d):
    pseudo = src + dst + bytes([0, 17]) + u16(len(d))
    c = csum(pseudo + d[:6] + b"\0\0" + d[8:])
    return 0xFFFF if c == 0 else c


def icmp(ty, code, ident, seq, data, check=None):
    m = bytearray([ty, code, 0, 0]) + u16(ident) + u16(seq) + bytes(data)
    m[2:4] = u16(csum(bytes(m)) if check is None else check)
    return bytes(m)


def pad(f):
    return f + b"\0" * (60 - len(f)) if len(f) < 60 else f


# The frames the stack sends.

def arp_reply_to(sha, spa):
    return pad(eth(sha, MAC, 0x0806, arp(2, MAC, US, sha, spa)))


def arp_request_for(tpa):
    return pad(eth(BC, MAC, 0x0806, arp(1, MAC, US, ZERO, tpa)))


def icmp_reply(mac, dst, ident, icmp_id, seq, data):
    return pad(eth(mac, MAC, 0x0800,
                   ipv4(US, dst, 1, icmp(0, 0, icmp_id, seq, data), ident=ident)))


def udp_echo(mac, dst, ident, dport, payload):
    return pad(eth(mac, MAC, 0x0800,
                   ipv4(US, dst, 17, udp(US, dst, 7, dport, payload), ident=ident)))


PING_DATA = bytes(range(56))


def ping(ident):
    return eth(GWMAC, MAC, 0x0800, ipv4(US, GW, 1, icmp(8, 0, 0x4C34, 1, PING_DATA), ident=ident))


# Frames to the stack.

def echo_request(src=GW, mac=GWMAC, icmp_id=0x1234, seq=1, data=b"abcdefghijklmnop",
                 dst=US, dst_mac=MAC, **kw):
    return eth(dst_mac, mac, 0x0800, ipv4(src, dst, 1, icmp(8, 0, icmp_id, seq, data), **kw))


def datagram(payload, src=GW, mac=GWMAC, sport=40000, dport=7, dst=US, dst_mac=MAC,
             checksum=True, ipkw=None, **ukw):
    return eth(dst_mac, mac, 0x0800,
               ipv4(src, dst, 17, udp(src, dst, sport, dport, payload, checksum, **ukw),
                    **(ipkw or {})))


def gateway_reply():
    return eth(MAC, GWMAC, 0x0806, arp(2, GWMAC, GW, MAC, US))


def arp_request_from(spa, sha, tpa=US, dst=BC):
    return eth(dst, sha, 0x0806, arp(1, sha, spa, ZERO, tpa))


def arp_reply_from(spa, sha, tpa=US, tha=MAC, dst=MAC):
    return eth(dst, sha, 0x0806, arp(2, sha, spa, tha, tpa))


def payload(k, n):
    """xtask's datagram k of n bytes."""
    head = b"uL4E" + k.to_bytes(4, "little")
    body = bytes((k + 3 * j) % 256 for j in range(8, max(n, 8)))
    return (head + body)[:n]


# The goldens' layout, as the Rust test writes it.

def fields(b, widths):
    out = []
    at = 0
    for w in widths:
        if at + w > len(b):
            break
        out.append(b[at:at + w].hex())
        at += w
    for i in range(at, len(b), 4):
        out.append(b[i:i + 4].hex())
    return " ".join(out)


def g16(b, at):
    return b[at] << 8 | b[at + 1]


def layout(f):
    lines = []

    def rest(b):
        for i in range(0, len(b), 16):
            lines.append(fields(b[i:i + 16], []))

    if len(f) < 14:
        rest(f)
        return lines or [""]
    lines.append(fields(f[:14], [6, 6, 2]))
    body = f[14:]
    ty = g16(f, 12)
    if ty == 0x0806 and len(body) >= 28:
        lines.append(fields(body[:28], [2, 2, 1, 1, 2, 6, 4, 6, 4]))
        rest(body[28:])
    elif ty == 0x0800 and len(body) >= 20:
        hl = (body[0] & 0xF) * 4
        total = g16(body, 2)
        if hl < 20 or hl > len(body):
            rest(body)
            return lines
        lines.append(fields(body[:hl], [1, 1, 2, 2, 2, 1, 1, 2, 4, 4]))
        end = min(max(total, hl), len(body))
        l4 = body[hl:end]
        at = 0
        if body[9] == 17 and len(l4) >= 8:
            lines.append(fields(l4[:8], [2, 2, 2, 2]))
            at = 8
        elif body[9] == 1 and len(l4) >= 8:
            lines.append(fields(l4[:8], [1, 1, 2, 2, 2]))
            at = 8
        rest(l4[at:])
        rest(body[end:])
    else:
        rest(body)
    return lines


def ip4(b):
    return ".".join(str(x) for x in b[:4])


def macs(b):
    return ":".join("%02x" % x for x in b[:6])


def describe(f):
    if len(f) < 14:
        return "%d bytes" % len(f)
    body = f[14:]
    ty = g16(f, 12)
    if ty == 0x0806 and len(body) >= 28:
        op = g16(body, 6)
        if op == 1:
            s = "ARP request: who has %s? tell %s" % (ip4(body[24:]), ip4(body[14:]))
        elif op == 2:
            s = "ARP reply: %s is at %s, to %s" % (ip4(body[14:]), macs(body[8:]), ip4(body[24:]))
        else:
            s = "ARP op %d" % op
    elif ty == 0x0800 and len(body) >= 20:
        hl = (body[0] & 0xF) * 4
        total = g16(body, 2)
        s = "%s > %s, id %d" % (ip4(body[12:]), ip4(body[16:]), g16(body, 4))
        if 20 <= hl <= total <= len(body):
            l4 = body[hl:total]
            if body[9] == 1 and len(l4) >= 8:
                what = {(0, 0): "echo reply", (8, 0): "echo request"}.get(
                    (l4[0], l4[1]), "type %d code %d" % (l4[0], l4[1]))
                s += ": ICMP %s, id %#06x seq %d, %d bytes" % (what, g16(l4, 4), g16(l4, 6), len(l4) - 8)
            elif body[9] == 17 and len(l4) >= 8:
                s += ": UDP %d > %d, %d bytes" % (g16(l4, 0), g16(l4, 2), len(l4) - 8)
            elif body[9] not in (1, 17):
                s += ": protocol %d" % body[9]
            else:
                s += ": protocol %d" % body[9]
    else:
        s = "EtherType %#06x" % ty
    return s + "; %d bytes" % len(f)


def out_lines(f):
    ls = layout(f)
    first = "out: %s  # %s" % (ls[0], describe(f))
    return [first] + ["     " + l for l in ls[1:]]


def in_lines(f, comment=None):
    ls = layout(f)
    c = comment if comment else describe(f)
    first = "in: %s  # %s" % (ls[0], c)
    if ls[0] == "":
        first = "in:  # %s" % c
    return [first] + ["    " + l for l in ls[1:]]


ROOT = None
WRITTEN = []


class Case:
    def __init__(self, group, name, comment, config="10.0.2.15/24 via 10.0.2.2", mac=MAC):
        self.group, self.name = group, name
        self.lines = ["# " + l for l in comment.strip().split("\n")]
        self.lines.append("config: %s, MAC %s" % (config, macs(mac)))
        self.auto = dict(frames_in=0, frames_out=0, arp_sent=0, ping_sent=0, udp_echoed=0)
        self.extra = {}

    def note(self, text):
        for l in text.strip().split("\n"):
            self.lines.append("# " + l)
        return self

    def _expect(self, outs, events):
        for f in outs:
            self.lines += out_lines(f)
            self.auto["frames_out"] += 1
            ty = g16(f, 12)
            if ty == 0x0806 and g16(f, 20) == 1:
                self.auto["arp_sent"] += 1
            if ty == 0x0800 and f[23] == 17:
                self.auto["udp_echoed"] += 1
            if ty == 0x0800 and f[23] == 1 and f[34] == 8:
                self.auto["ping_sent"] += 1
        for e in events:
            self.lines.append("event: " + e)

    def start(self, outs=(), events=()):
        self.lines.append("start:")
        self._expect(outs, events)
        return self

    def input(self, f, comment=None, outs=(), events=()):
        self.lines += in_lines(f, comment)
        self.auto["frames_in"] += 1
        self._expect(outs, events)
        return self

    def add(self, **c):
        for k, v in c.items():
            self.extra[k] = self.extra.get(k, 0) + v
        return self

    def tx(self, n):
        self.lines.append("tx: %s" % n)
        return self

    def stats(self, **c):
        for k in c:
            assert k in NAMES, k
            assert k not in self.auto, k
        c.update(self.auto)
        for k, v in self.extra.items():
            c[k] = c.get(k, 0) + v
        parts = ["%s=%d" % (k, c[k]) for k in NAMES if c.get(k)]
        self.lines.append("stats: " + " ".join(parts))
        d = os.path.join(ROOT, self.group)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, self.name + ".golden")
        assert path not in WRITTEN, path
        WRITTEN.append(path)
        with open(path, "w") as fh:
            fh.write("\n".join(self.lines) + "\n")


GATEWAY_EVENT = "net: gateway 10.0.2.2 is at 52:55:0a:00:02:02"


def with_gateway(c):
    """The gateway's ARP reply, which every case that answers it needs first."""
    c.input(gateway_reply(), "the gateway's ARP reply: the stack learns its MAC",
            events=[GATEWAY_EVENT])
    c.add(arp_learnt=1)
    return c

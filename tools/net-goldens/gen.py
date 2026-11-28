"""Writes net's golden cases: python3 -I tools/net-goldens/gen.py <user/net/golden>,
then extra.py. Starts from an empty directory: it removes the one it is given."""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa: E402
from lib import *  # noqa: E402,F401,F403

lib.ROOT = sys.argv[1]
if os.path.isdir(lib.ROOT):
    shutil.rmtree(lib.ROOT)
os.makedirs(lib.ROOT)

H3, M3 = host(3)
H4, M4 = host(4)
H5, M5 = host(5)
FAR = ip("93.184.216.34")
DATA = b"abcdefghijklmnop"


def answered(group, name, comment, req, reply_of, **stats):
    """A case whose one request, after the gateway's reply, is answered."""
    c = with_gateway(Case(group, name, comment))
    c.input(req, outs=[reply_of(1)])
    c.stats(**stats)


def dropped(group, name, comment, frame, counter, gateway=True, frame_comment=None):
    c = Case(group, name, comment)
    if gateway:
        with_gateway(c)
    c.input(frame, frame_comment)
    c.stats(**{counter: 1})


# ---------------------------------------------------------------- ethernet
G = "ethernet"
dropped(G, "empty_frame", "A frame of no bytes is shorter than a header.", b"", "eth_short", False)
dropped(G, "13_bytes", "13 bytes are one short of an Ethernet header.",
        echo_request()[:13], "eth_short", False)
dropped(G, "header_alone_ipv4",
        "A bare header of type IPv4 passes Ethernet; IPv4 finds no packet.",
        echo_request()[:14], "ip_malformed", False)
dropped(G, "header_alone_arp",
        "A bare header of type ARP passes Ethernet; ARP finds no body.",
        gateway_reply()[:14], "arp_malformed", False)
big = echo_request(data=bytes(i % 256 for i in range(1472)))
assert len(big) == 1514
answered(G, "1514_bytes_taken",
         "The largest frame, 1,514 bytes: a 1,500-byte packet.",
         big, lambda i: icmp_reply(GWMAC, GW, i, 0x1234, 1, bytes(i % 256 for i in range(1472))),
         icmp_answered=1)
dropped(G, "1515_bytes", "One byte more than the largest frame, even as padding.",
        big + b"\0", "eth_long", False)
dropped(G, "to_another_mac", "A frame to another station's MAC.",
        echo_request(dst_mac=bytes([2, 0, 0, 0, 0, 0x99])), "eth_not_ours")
dropped(G, "to_an_ipv4_multicast_mac", "A frame to IPv4 multicast's 01:00:5e:00:00:01.",
        echo_request(dst=ip("224.0.0.1"), dst_mac=bytes([1, 0, 0x5E, 0, 0, 1])), "eth_not_ours")
dropped(G, "to_an_ipv6_multicast_mac", "A frame to IPv6 multicast's 33:33:00:00:00:01.",
        echo_request(dst_mac=bytes([0x33, 0x33, 0, 0, 0, 1])), "eth_not_ours")
c = Case(G, "to_broadcast_taken", "A broadcast frame is taken: an ARP request for the stack.")
c.input(arp_request_from(GW, GWMAC), outs=[arp_reply_to(GWMAC, GW)], events=[GATEWAY_EVENT])
c.stats(arp_answered=1)
dropped(G, "vlan_tag", "An 802.1Q tag (0x8100) is another EtherType: no VLANs.",
        eth(MAC, GWMAC, 0x8100, bytes([0, 5, 8, 0]) + echo_request()[14:]), "eth_type")
dropped(G, "ipv6", "IPv6 (0x86DD) is another EtherType.",
        eth(MAC, GWMAC, 0x86DD, bytes(40)), "eth_type")
dropped(G, "lldp", "LLDP (0x88CC) to its multicast MAC is another destination first.",
        eth(bytes([1, 0x80, 0xC2, 0, 0, 0x0E]), GWMAC, 0x88CC, bytes(30)), "eth_not_ours")
dropped(G, "other_ethertype", "An EtherType of 0x0801 to the stack's MAC.",
        eth(MAC, GWMAC, 0x0801, echo_request()[14:]), "eth_type")
small = echo_request(data=b"hi")
assert len(small) == 44
answered(G, "padding_past_the_packet_ignored",
         "A short echo request padded to 60 bytes, as a NIC pads it: the padding\n"
         "is not data, so the reply carries two bytes and is padded itself.",
         small + bytes(16), lambda i: icmp_reply(GWMAC, GW, i, 0x1234, 1, b"hi"),
         icmp_answered=1)
c = Case(G, "padding_past_the_arp_body_ignored",
         "An ARP request padded to 60 bytes is answered.")
c.input(arp_request_from(GW, GWMAC) + bytes(18), outs=[arp_reply_to(GWMAC, GW)],
        events=[GATEWAY_EVENT])
c.stats(arp_answered=1)
c = with_gateway(Case(G, "nothing_learnt_from_the_source_mac",
                      "An echo request from the gateway's address but another source MAC:\n"
                      "the reply goes to the MAC ARP gave, not the frame's source."))
c.input(echo_request(mac=bytes([2, 0, 0, 0, 0, 0x42])),
        outs=[icmp_reply(GWMAC, GW, 1, 0x1234, 1, DATA)])
c.stats(icmp_answered=1)
c = Case(G, "replies_are_padded_to_60", "An ARP reply is 42 bytes, sent as 60 with zeros.")
c.input(arp_request_from(H3, M3), outs=[arp_reply_to(M3, H3)])
c.stats(arp_answered=1)

# ---------------------------------------------------------------- arp
G = "arp"
c = Case(G, "request_for_us_answered",
         "An ARP request for the stack's address is answered, and its sender\n"
         "learnt: the echo reply that follows needs no request of its own.")
c.input(arp_request_from(H3, M3), outs=[arp_reply_to(M3, H3)])
c.input(echo_request(H3, M3), outs=[icmp_reply(M3, H3, 1, 0x1234, 1, DATA)])
c.stats(arp_answered=1, icmp_answered=1)

c = Case(G, "request_in_a_unicast_frame_answered",
         "A request sent to the stack's MAC, as a host checking its entry does.")
c.input(arp_request_from(H3, M3, dst=MAC), outs=[arp_reply_to(M3, H3)])
c.stats(arp_answered=1)

c = Case(G, "request_for_another_not_learnt",
         "A request for another address is not answered, and its sender, not\n"
         "in the cache, is not added: the echo reply must ask for it.")
c.input(arp_request_from(H3, M3, tpa=H4))
c.input(echo_request(H3, M3), outs=[arp_request_for(H3)])
c.stats(arp_not_ours=1, icmp_answered=1)

c = Case(G, "request_for_another_merges",
         "RFC 826's merge: a sender already in the cache, here pending with an\n"
         "echo reply waiting, is updated by any ARP packet, one for another\n"
         "address included, and the waiting packet goes out.")
c.input(echo_request(H3, M3), outs=[arp_request_for(H3)])
c.input(arp_request_from(H3, M3, tpa=H4), outs=[icmp_reply(M3, H3, 1, 0x1234, 1, DATA)])
c.stats(arp_not_ours=1, icmp_answered=1)

c = Case(G, "reply_learnt",
         "An ARP reply to the stack is learnt, asked for or not.")
c.input(arp_reply_from(H3, M3))
c.input(echo_request(H3, M3), outs=[icmp_reply(M3, H3, 1, 0x1234, 1, DATA)])
c.stats(arp_learnt=1, icmp_answered=1)

c = Case(G, "reply_for_another_not_learnt",
         "A reply to another address teaches nothing about a new sender.")
c.input(arp_reply_from(H3, M3, tpa=H4, tha=M4, dst=BC))
c.input(echo_request(H3, M3), outs=[arp_request_for(H3)])
c.stats(arp_not_ours=1, icmp_answered=1)

M3b = bytes([2, 0, 0, 0, 0, 0x33])
c = Case(G, "merge_updates_the_mac",
         "A known sender's request for another address moves it to a new MAC.")
c.input(arp_request_from(H3, M3), outs=[arp_reply_to(M3, H3)])
c.input(arp_request_from(H3, M3b, tpa=H4))
c.input(echo_request(H3, M3b), outs=[icmp_reply(M3b, H3, 1, 0x1234, 1, DATA)])
c.stats(arp_answered=1, arp_not_ours=1, icmp_answered=1)

c = Case(G, "reply_updates_the_mac", "A later reply moves a known sender to a new MAC.")
c.input(arp_reply_from(H3, M3))
c.input(arp_reply_from(H3, M3b))
c.input(echo_request(H3, M3b), outs=[icmp_reply(M3b, H3, 1, 0x1234, 1, DATA)])
c.stats(arp_learnt=2, icmp_answered=1)


def bad_arp(name, comment, body, counter="arp_malformed"):
    c = Case(G, name, comment)
    c.input(eth(BC, M3, 0x0806, body))
    c.stats(**{counter: 1})


bad_arp("hardware_type_6", "Hardware type 6 (IEEE 802) is not Ethernet.",
        arp(1, M3, H3, ZERO, US, htype=6))
bad_arp("protocol_ipv6", "Protocol 0x86DD is not IPv4.", arp(1, M3, H3, ZERO, US, ptype=0x86DD))
bad_arp("hardware_length_8", "A hardware length of 8, not 6.", arp(1, M3, H3, ZERO, US, hlen=8))
bad_arp("protocol_length_16", "A protocol length of 16, not 4.", arp(1, M3, H3, ZERO, US, plen=16))
bad_arp("operation_3", "Operation 3, a RARP request.", arp(3, M3, H3, ZERO, US))
bad_arp("operation_0", "Operation 0.", arp(0, M3, H3, ZERO, US))
bad_arp("body_27_bytes", "A body one byte short.", arp(1, M3, H3, ZERO, US)[:27])
bad_arp("probe_from_0",
        "RFC 5227's probe for the stack's address, from 0.0.0.0: a bad sender,\n"
        "neither answered nor learnt.", arp(1, M3, bytes(4), ZERO, US), "arp_bad_sender")
bad_arp("sender_255_255_255_255", "A sender address of 255.255.255.255.",
        arp(1, M3, BCAST, ZERO, US), "arp_bad_sender")
bad_arp("sender_the_subnet_broadcast", "A sender address of 10.0.2.255.",
        arp(1, M3, ip("10.0.2.255"), ZERO, US), "arp_bad_sender")
bad_arp("sender_multicast", "A sender address of 224.0.0.251.",
        arp(1, M3, ip("224.0.0.251"), ZERO, US), "arp_bad_sender")
bad_arp("sender_is_us",
        "Another station claims the stack's address: neither answered nor\n"
        "defended (no gratuitous ARP).", arp(1, M3, US, ZERO, US), "arp_bad_sender")
bad_arp("sender_mac_broadcast", "A sender MAC of ff:ff:ff:ff:ff:ff.",
        arp(1, BC, H3, ZERO, US), "arp_bad_sender")
bad_arp("sender_mac_multicast", "A sender MAC with the group bit, 01:00:5e:00:00:01.",
        arp(1, bytes([1, 0, 0x5E, 0, 0, 1]), H3, ZERO, US), "arp_bad_sender")
bad_arp("sender_mac_zero", "A sender MAC of 0.", arp(1, ZERO, H3, ZERO, US), "arp_bad_sender")
bad_arp("sender_mac_ours", "A sender MAC that is the stack's own.",
        arp(1, MAC, H3, ZERO, US), "arp_bad_sender")

c = Case(G, "gratuitous_from_a_stranger_not_learnt",
         "A gratuitous ARP (sender and target both 10.0.2.3) from a host not in\n"
         "the cache is for another address: nothing learnt.")
c.input(eth(BC, M3, 0x0806, arp(1, M3, H3, ZERO, H3)))
c.input(echo_request(H3, M3), outs=[arp_request_for(H3)])
c.stats(arp_not_ours=1, icmp_answered=1)

c = Case(G, "gratuitous_updates_a_known_host",
         "A gratuitous ARP from a host in the cache moves it to its new MAC.")
c.input(arp_request_from(H3, M3), outs=[arp_reply_to(M3, H3)])
c.input(eth(BC, M3b, 0x0806, arp(1, M3b, H3, ZERO, H3)))
c.input(echo_request(H3, M3b), outs=[icmp_reply(M3b, H3, 1, 0x1234, 1, DATA)])
c.stats(arp_answered=1, arp_not_ours=1, icmp_answered=1)

c = Case(G, "the_cache_holds_eight",
         "Eight hosts each ask for the stack and are learnt; an echo request\n"
         "from each is answered without a request.")
ident = 1
for n in range(3, 11):
    h, m = host(n)
    c.input(arp_request_from(h, m), outs=[arp_reply_to(m, h)])
for n in range(3, 11):
    h, m = host(n)
    c.input(echo_request(h, m), outs=[icmp_reply(m, h, ident, 0x1234, 1, DATA)])
    ident += 1
c.stats(arp_answered=8, icmp_answered=8)

c = Case(G, "the_least_recently_used_is_replaced",
         "Eight hosts are learnt, 10.0.2.3 first; an echo request from it makes\n"
         "10.0.2.4 the least recently used, which a ninth host replaces.")
for n in range(3, 11):
    h, m = host(n)
    c.input(arp_request_from(h, m), outs=[arp_reply_to(m, h)])
c.input(echo_request(H3, M3), outs=[icmp_reply(M3, H3, 1, 0x1234, 1, DATA)])
h11, m11 = host(11)
c.input(arp_request_from(h11, m11), outs=[arp_reply_to(m11, h11)])
c.note("10.0.2.4 is gone: its echo reply waits for a request; 10.0.2.3's does not.")
c.input(echo_request(H4, M4), outs=[arp_request_for(H4)])
c.input(echo_request(H3, M3), outs=[icmp_reply(M3, H3, 3, 0x1234, 1, DATA)])
c.stats(arp_answered=9, icmp_answered=3)

c = Case(G, "start_asks_for_the_gateway",
         "Stack::start sends one ARP request for the gateway and no gratuitous\n"
         "ARP; the gateway's reply is learnt and reported once.")
c.start(outs=[arp_request_for(GW)])
c.input(gateway_reply(), outs=[ping(1)], events=[GATEWAY_EVENT])
c.input(gateway_reply())
c.stats(arp_learnt=2)

c = Case(G, "start_twice_asks_once", "Only the first Stack::start sends anything.")
c.start(outs=[arp_request_for(GW)])
c.start()
c.stats()

c = Case(G, "a_reply_from_beyond_the_subnet_is_learnt",
         "A reply to the stack from outside its subnet is learnt like any other,\n"
         "but packets to that address go through the gateway.")
far_mac = bytes([2, 0, 0, 0, 0, 0x77])
c.input(arp_reply_from(FAR, far_mac))
c.input(gateway_reply(), events=[GATEWAY_EVENT])
c.input(echo_request(FAR, GWMAC), outs=[icmp_reply(GWMAC, FAR, 1, 0x1234, 1, DATA)])
c.stats(arp_learnt=2, icmp_answered=1)

# ---------------------------------------------------------------- ipv4
G = "ipv4"


def reply1(i):
    return icmp_reply(GWMAC, GW, i, 0x1234, 1, DATA)


def raw_request(**kw):
    """An echo request from the gateway with header fields set by hand."""
    return eth(MAC, GWMAC, 0x0800, ipv4(GW, US, 1, icmp(8, 0, 0x1234, 1, DATA), **kw))


answered(G, "echo_request_answered",
         "An echo request from the gateway: the reply has version 4, IHL 5,\n"
         "TOS 0, identification 1, DF, TTL 64 and its checksum.",
         echo_request(), reply1, icmp_answered=1)
dropped(G, "version_6", "Version 6 in an IPv4 frame, its checksum right.",
        raw_request(version=6), "ip_malformed")
dropped(G, "ihl_4", "An IHL of 4: a header shorter than 20 bytes.", raw_request(ihl=4), "ip_malformed")
dropped(G, "ihl_past_the_packet", "An IHL of 15 (60 bytes) in a 44-byte packet.",
        raw_request(ihl=15), "ip_malformed")
dropped(G, "total_length_under_the_header", "A total length of 19.",
        raw_request(total=19), "ip_malformed")
dropped(G, "total_length_past_the_frame", "A total length one past the bytes the frame holds.",
        raw_request(total=45), "ip_malformed")
dropped(G, "shorter_than_a_header", "19 bytes of IPv4.",
        echo_request()[:14 + 19], "ip_malformed")
dropped(G, "header_checksum_wrong", "The header checksum off by one.",
        raw_request(check=(g16(raw_request()[14:], 10) + 1) & 0xFFFF), "ip_checksum")
dropped(G, "header_checksum_zero", "A header checksum of 0, as if none were computed.",
        raw_request(check=0), "ip_checksum")
answered(G, "options_skipped",
         "A router alert option (IHL 6) is skipped unread; the reply has none.",
         raw_request(options=bytes([0x94, 4, 0, 0])), reply1, icmp_answered=1)
answered(G, "forty_bytes_of_options",
         "IHL 15: 40 bytes of options, NOPs then an end of list.",
         raw_request(options=bytes([1] * 39 + [0])), reply1, icmp_answered=1)
dropped(G, "more_fragments", "MF set: a first fragment. Nothing is reassembled.",
        raw_request(flags=0x2000), "ip_fragment")
dropped(G, "fragment_offset", "A last fragment, at offset 185 (1,480 bytes).",
        raw_request(flags=185), "ip_fragment")
answered(G, "no_df_taken", "A request without DF is taken: only fragments are refused.",
         raw_request(flags=0), reply1, icmp_answered=1)
answered(G, "reserved_flag_ignored", "The reserved flag bit is ignored.",
         raw_request(flags=0xC000), reply1, icmp_answered=1)
dropped(G, "to_another_address", "To 10.0.2.16, in a frame to the stack's MAC.",
        echo_request(dst=ip("10.0.2.16")), "ip_not_ours")
dropped(G, "to_the_subnet_broadcast", "To 10.0.2.255: only 255.255.255.255 is taken.",
        echo_request(dst=ip("10.0.2.255"), dst_mac=BC), "ip_not_ours")
dropped(G, "to_the_network_address", "To 10.0.2.0.", echo_request(dst=ip("10.0.2.0")), "ip_not_ours")
dropped(G, "to_a_multicast_group", "To 224.0.0.1, in a frame to the stack's MAC.",
        echo_request(dst=ip("224.0.0.1")), "ip_not_ours")
dropped(G, "to_255_255_255_255_reaches_icmp",
        "To 255.255.255.255: IPv4 takes it, and ICMP refuses an echo request\n"
        "to broadcast.", echo_request(dst=BCAST, dst_mac=BC), "icmp_broadcast")
dropped(G, "from_0", "From 0.0.0.0.", echo_request(src=bytes(4)), "ip_bad_source")
dropped(G, "from_255_255_255_255", "From 255.255.255.255.", echo_request(src=BCAST), "ip_bad_source")
dropped(G, "from_the_subnet_broadcast", "From 10.0.2.255.",
        echo_request(src=ip("10.0.2.255")), "ip_bad_source")
dropped(G, "from_multicast", "From 239.1.2.3.", echo_request(src=ip("239.1.2.3")), "ip_bad_source")
dropped(G, "from_ourselves", "From the stack's own address: a loop or a spoof.",
        echo_request(src=US), "ip_bad_source")
dropped(G, "protocol_tcp", "TCP (6): no TCP.",
        eth(MAC, GWMAC, 0x0800, ipv4(GW, US, 6, bytes(20))), "ip_protocol")
dropped(G, "protocol_igmp", "IGMP (2).", eth(MAC, GWMAC, 0x0800, ipv4(GW, US, 2, bytes(8))), "ip_protocol")
answered(G, "bytes_past_the_total_length_ignored",
         "Eight bytes past the total length inside the frame are padding, not data.",
         echo_request() + b"PADPADPA", reply1, icmp_answered=1)
answered(G, "ttl_and_tos_not_copied",
         "A request with TTL 1 and TOS 0x10: the reply has TTL 64 and TOS 0.",
         raw_request(ttl=1, tos=0x10), reply1, icmp_answered=1)

c = with_gateway(Case(G, "beyond_the_subnet_through_the_gateway",
                      "A request from 93.184.216.34: the reply goes to the gateway's MAC."))
c.input(echo_request(FAR, GWMAC), outs=[icmp_reply(GWMAC, FAR, 1, 0x1234, 1, DATA)])
c.stats(icmp_answered=1)

c = Case(G, "in_the_subnet_straight_to_the_host",
         "A request from 10.0.2.3 is answered to 10.0.2.3 itself, which ARP must\n"
         "find first: the reply waits, and a request for 10.0.2.3 goes out.")
c.input(echo_request(H3, M3), outs=[arp_request_for(H3)])
c.input(arp_reply_from(H3, M3), outs=[icmp_reply(M3, H3, 1, 0x1234, 1, DATA)])
c.stats(icmp_answered=1, arp_learnt=1)

c = with_gateway(Case(G, "identification_counts_up",
                      "Each packet sent takes the next identification, from 1."))
for i in range(1, 4):
    c.input(echo_request(seq=i), outs=[icmp_reply(GWMAC, GW, i, 0x1234, i, DATA)])
c.stats(icmp_answered=3)

# ---------------------------------------------------------------- icmp
G = "icmp"


def icmp_from_gw(msg, **kw):
    return eth(MAC, GWMAC, 0x0800, ipv4(GW, US, 1, msg, **kw))


answered(G, "echo_request", "An echo request: its identifier, sequence and data come back.",
         echo_request(icmp_id=0xBEEF, seq=0xFFFF, data=b"The quick brown fox"),
         lambda i: icmp_reply(GWMAC, GW, i, 0xBEEF, 0xFFFF, b"The quick brown fox"),
         icmp_answered=1)
answered(G, "echo_request_without_data", "An 8-byte echo request: the header alone.",
         echo_request(data=b""), lambda i: icmp_reply(GWMAC, GW, i, 0x1234, 1, b""),
         icmp_answered=1)
answered(G, "echo_request_odd_data", "33 bytes of data: the checksum pads the last byte.",
         echo_request(data=bytes(range(33))),
         lambda i: icmp_reply(GWMAC, GW, i, 0x1234, 1, bytes(range(33))), icmp_answered=1)
answered(G, "echo_request_of_56_bytes", "ping's default: 56 bytes of data.",
         echo_request(icmp_id=0x0D4A, data=bytes(range(0x10, 0x48))),
         lambda i: icmp_reply(GWMAC, GW, i, 0x0D4A, 1, bytes(range(0x10, 0x48))),
         icmp_answered=1)
big = bytes((7 * j) % 256 for j in range(1472))
answered(G, "echo_request_of_1472_bytes", "The largest echo request: a 1,514-byte frame.",
         echo_request(data=big), lambda i: icmp_reply(GWMAC, GW, i, 0x1234, 1, big),
         icmp_answered=1)
good = icmp(8, 0, 0x1234, 1, DATA)
dropped(G, "checksum_wrong", "The ICMP checksum off by one.",
        icmp_from_gw(icmp(8, 0, 0x1234, 1, DATA, check=(g16(good, 2) + 1) & 0xFFFF)),
        "icmp_checksum")
dropped(G, "checksum_zero", "An ICMP checksum of 0.",
        icmp_from_gw(icmp(8, 0, 0x1234, 1, DATA, check=0)), "icmp_checksum")
dropped(G, "seven_bytes", "Seven bytes: shorter than an ICMP header.",
        icmp_from_gw(good[:7]), "icmp_short")
dropped(G, "echo_request_code_1", "Type 8 with code 1 is not an echo request.",
        icmp_from_gw(icmp(8, 1, 0x1234, 1, DATA)), "icmp_other")
dropped(G, "destination_unreachable", "Type 3, code 3: nothing answers it.",
        icmp_from_gw(icmp(3, 3, 0, 0, bytes(28))), "icmp_other")
dropped(G, "timestamp_request", "Type 13: only echo is answered.",
        icmp_from_gw(icmp(13, 0, 1, 1, bytes(12))), "icmp_other")
dropped(G, "to_255_255_255_255", "An echo request to 255.255.255.255 is never answered.",
        echo_request(dst=BCAST, dst_mac=BC), "icmp_broadcast")
dropped(G, "to_us_in_a_broadcast_frame",
        "An echo request to the stack's address in a broadcast frame is a broadcast\n"
        "too: not answered.", echo_request(dst_mac=BC), "icmp_broadcast")
answered(G, "echo_request_from_beyond_the_gateway",
         "From 192.0.2.7: answered through the gateway.",
         echo_request(src=ip("192.0.2.7")),
         lambda i: icmp_reply(GWMAC, ip("192.0.2.7"), i, 0x1234, 1, DATA), icmp_answered=1)

PING_EVENT = "net: ping 10.0.2.2: reply 1, 56 bytes"


def pinged(name, comment):
    c = Case(G, name, comment)
    c.start(outs=[arp_request_for(GW)])
    c.input(gateway_reply(), outs=[ping(1)], events=[GATEWAY_EVENT])
    c.add(arp_learnt=1)
    return c


def ping_reply(icmp_id=0x4C34, seq=1, data=PING_DATA, src=GW, dst=US, dst_mac=MAC):
    return eth(dst_mac, GWMAC, 0x0800, ipv4(src, dst, 1, icmp(0, 0, icmp_id, seq, data)))


c = pinged("the_ping_answered",
           "Stack::start asks for the gateway; its reply sends the stack's echo\n"
           "request (identifier 0x4c34, sequence 1, 56 bytes); the gateway's\n"
           "echo reply is counted and reported.")
c.input(ping_reply(), events=[PING_EVENT])
c.stats(icmp_replies=1)

c = pinged("the_ping_answered_twice_reported_once",
           "A second matching reply is counted, not reported again.")
c.input(ping_reply(), events=[PING_EVENT])
c.input(ping_reply())
c.stats(icmp_replies=2)

c = pinged("a_reply_reports_its_length", "The report gives the reply's data length.")
c.input(ping_reply(data=PING_DATA[:20]), events=["net: ping 10.0.2.2: reply 1, 20 bytes"])
c.stats(icmp_replies=1)

c = pinged("a_reply_with_another_identifier", "An echo reply with another identifier.")
c.input(ping_reply(icmp_id=0x4C35))
c.stats(icmp_other=1)

c = pinged("a_reply_with_another_sequence", "An echo reply with sequence 2.")
c.input(ping_reply(seq=2))
c.stats(icmp_other=1)

c = pinged("a_reply_from_another_host", "A matching echo reply, but from 10.0.2.3.")
c.input(ping_reply(src=H3))
c.stats(icmp_other=1)

c = pinged("a_reply_to_broadcast", "A matching echo reply sent to 255.255.255.255.")
c.input(ping_reply(dst=BCAST, dst_mac=BC))
c.stats(icmp_other=1)

c = with_gateway(Case(G, "a_reply_before_the_ping",
                      "Without Stack::start no request went out: a matching reply is\n"
                      "some other host's."))
c.input(ping_reply())
c.stats(icmp_other=1)

# ---------------------------------------------------------------- udp
G = "udp"


def udp_from_gw(d, **kw):
    return eth(MAC, GWMAC, 0x0800, ipv4(GW, US, 17, d, **kw))


def echo1(dport=40000, p=b"hello, echo"):
    return lambda i: udp_echo(GWMAC, GW, i, dport, p)


answered(G, "a_datagram_to_port_7", "A datagram to port 7 is echoed.",
         datagram(b"hello, echo"), echo1(), udp_received=1)
dropped(G, "length_7", "A UDP length of 7: under its own header.",
        datagram(b"hello, echo", length=7), "udp_length")
dropped(G, "length_past_the_ip_payload", "A UDP length one past the IP payload.",
        datagram(b"hello, echo", length=20), "udp_length")
dropped(G, "seven_bytes", "Seven bytes of IP payload: no UDP header.",
        udp_from_gw(udp(GW, US, 40000, 7, b"")[:7]), "udp_length")
answered(G, "bytes_past_the_length_ignored",
         "A UDP length of 13 in a 19-byte IP payload: the last 6 bytes are not\n"
         "the datagram's, and the checksum covers the 13.",
         udp_from_gw(udp(GW, US, 40000, 7, b"hello") + b"ignore"), echo1(p=b"hello"),
         udp_received=1)
answered(G, "no_checksum_taken",
         "A checksum of 0 means none, which IPv4 allows; the echo has one.",
         datagram(b"hello, echo", checksum=False), echo1(), udp_received=1)
good = udp(GW, US, 40000, 7, b"hello, echo")
dropped(G, "checksum_wrong", "The UDP checksum off by one.",
        datagram(b"hello, echo", check=(g16(good, 6) + 1) & 0xFFFF), "udp_checksum")
dropped(G, "checksum_without_the_pseudo_header",
        "A checksum over the pseudo-header of another destination, 10.0.2.16.",
        datagram(b"hello, echo", pseudo_dst=ip("10.0.2.16")), "udp_checksum")
dropped(G, "to_port_9", "Port 9 (discard) has no service: dropped silently, with no ICMP\n"
        "port unreachable.", datagram(b"x", dport=9), "udp_port")
dropped(G, "to_port_0", "Port 0.", datagram(b"x", dport=0), "udp_port")
dropped(G, "to_port_53", "Port 53.", datagram(b"x", dport=53), "udp_port")
dropped(G, "to_port_7_from_port_0", "From port 0 there is no one to answer.",
        datagram(b"x", sport=0), "udp_refused")
dropped(G, "to_port_7_from_port_7", "From port 7: two echo services would loop.",
        datagram(b"x", sport=7), "udp_refused")
dropped(G, "to_255_255_255_255", "To port 7 at 255.255.255.255: no echo to broadcast.",
        datagram(b"x", dst=BCAST, dst_mac=BC), "udp_refused")
dropped(G, "to_us_in_a_broadcast_frame", "To the stack's address in a broadcast frame.",
        datagram(b"x", dst_mac=BC), "udp_refused")
dropped(G, "to_port_9_at_broadcast", "Another port at broadcast is dropped as another port.",
        datagram(b"x", dport=9, dst=BCAST, dst_mac=BC), "udp_port")

# ---------------------------------------------------------------- echo
G = "echo"


def echo_to(p, k):
    return lambda i: udp_echo(GWMAC, GW, i, 50000 + k, p)


for k, n in enumerate([0, 1, 8, 9, 17, 18, 19, 64, 255, 256, 512, 952, 953, 1471, 1472]):
    p = payload(k, n)
    answered(G, "payload_%d" % n,
             "xtask's datagram %d: %d bytes, echoed unchanged from port 7 to its\n"
             "source port." % (k, n),
             datagram(p, sport=50000 + k), echo_to(p, k), udp_received=1)
answered(G, "every_byte_value", "A payload of every byte value, 0 to 255, comes back unchanged.",
         datagram(bytes(range(256))), echo1(p=bytes(range(256))), udp_received=1)
answered(G, "to_the_source_port", "The echo goes to the source port, here 65535.",
         datagram(b"port", sport=65535), echo1(65535, b"port"), udp_received=1)
answered(G, "from_port_1024", "From port 1024, the lowest a reply may go to.",
         datagram(b"port", sport=1024), echo1(1024, b"port"), udp_received=1)
c = with_gateway(Case(G, "beyond_the_gateway",
                      "A datagram from 198.51.100.9: echoed to it through the gateway."))
c.input(datagram(b"far", src=ip("198.51.100.9")),
        outs=[udp_echo(GWMAC, ip("198.51.100.9"), 1, 40000, b"far")])
c.stats(udp_received=1)
dropped(G, "refuses_broadcast", "No echo to 255.255.255.255: no amplification.",
        datagram(b"amplify", dst=BCAST, dst_mac=BC), "udp_refused")
dropped(G, "refuses_broadcast_frame", "No echo of a datagram in a broadcast frame.",
        datagram(b"amplify", dst_mac=BC), "udp_refused")
dropped(G, "refuses_source_port_0", "No echo to port 0.", datagram(b"zero", sport=0), "udp_refused")
dropped(G, "refuses_source_port_7", "No echo to another echo service: no loop.",
        datagram(b"loop", sport=7), "udp_refused")
dropped(G, "refuses_source_port_19",
        "No echo to chargen, or any well-known port: a forged one would loop for good.",
        datagram(b"loop", sport=19), "udp_refused")
dropped(G, "refuses_source_port_1023", "No echo below port 1024, the first a client sends from.",
        datagram(b"well-known", sport=1023), "udp_refused")
dropped(G, "refuses_a_spoofed_broadcast_source",
        "A datagram from 10.0.2.255 is refused before UDP sees it.",
        datagram(b"spoof", src=ip("10.0.2.255")), "ip_bad_source")
for name, src in [("loopback", "127.0.0.1"), ("this_network", "0.1.2.3"),
                  ("reserved", "240.0.0.1")]:
    dropped(G, "refuses_a_%s_source" % name,
            "A datagram from %s, which no host has, is refused before UDP sees it\n"
            "(RFC 1122 3.2.1.3)." % src,
            datagram(b"martian", src=ip(src)), "ip_bad_source")
c = with_gateway(Case(G, "no_transmit_buffer",
                      "With no transmit buffer free the echo is dropped and counted."))
c.tx(0)
c.input(datagram(b"lost"))
c.tx("any")
c.input(datagram(b"found"), outs=[udp_echo(GWMAC, GW, 2, 40000, b"found")])
c.stats(udp_received=2, tx_full=1)
c = with_gateway(Case(G, "a_run_of_datagrams",
                      "Five datagrams, each echoed at once, each with the next identification."))
for i in range(1, 6):
    p = payload(i, 20 + i)
    c.input(datagram(p, sport=40000 + i), outs=[udp_echo(GWMAC, GW, i, 40000 + i, p)])
c.stats(udp_received=5)

# ---------------------------------------------------------------- checksum
G = "checksum"
answered(G, "udp_odd_length", "Three bytes: the pseudo-header sum pads the last with 0.",
         datagram(b"odd"), echo1(p=b"odd"), udp_received=1)


def zero_sum_payload(sport):
    """A payload whose datagram from the gateway to the stack sums to 0xffff,
    so its checksum computes to 0 and is sent as 0xffff."""
    base = b"zero!!"
    d = udp(GW, US, sport, 7, base + b"\0\0", checksum=False)
    pseudo = GW + US + bytes([0, 17]) + u16(len(d))
    s = ones_sum(pseudo + d)
    fix = (0xFFFF - s) & 0xFFFF
    p = base + u16(fix)
    d = udp(GW, US, sport, 7, p, checksum=False)
    assert ones_sum(pseudo + d) == 0xFFFF
    return p


zp = zero_sum_payload(40000)
c = with_gateway(Case(G, "a_sum_of_0xffff_is_sent_as_0xffff",
                      "This payload's datagram sums to 0xffff, so its checksum computes to\n"
                      "0, which UDP sends as 0xffff. The request carries 0xffff and\n"
                      "verifies; the echo's sum is the same, so it carries 0xffff too."))
req = datagram(zp)
assert g16(req, 40) == 0xFFFF
rep = udp_echo(GWMAC, GW, 1, 40000, zp)
assert g16(rep, 40) == 0xFFFF
c.input(req, outs=[rep])
c.stats(udp_received=1)
c = with_gateway(Case(G, "no_checksum_echoed_with_0xffff",
                      "The same payload without a checksum: the echo still carries 0xffff."))
c.input(datagram(zp, checksum=False), outs=[rep])
c.stats(udp_received=1)
dropped(G, "a_checksum_of_0xfffe", "0xfffe where 0xffff is right.",
        datagram(zp, check=0xFFFE), "udp_checksum")
answered(G, "carries_fold_back", "64 bytes of 0xff: every word carries.",
         datagram(b"\xff" * 64), echo1(p=b"\xff" * 64), udp_received=1)
answered(G, "the_header_with_options", "A header with options verifies over all 24 bytes.",
         raw_request(options=bytes([0x94, 4, 0, 0])), reply1, icmp_answered=1)
dropped(G, "the_options_changed", "A byte of the options changed, the checksum not.",
        (lambda f: f[:34] + b"\x95" + f[35:])(raw_request(options=bytes([0x94, 4, 0, 0]))),
        "ip_checksum")
answered(G, "icmp_odd_length", "One byte of data: ICMP's checksum pads it.",
         echo_request(data=b"!"), lambda i: icmp_reply(GWMAC, GW, i, 0x1234, 1, b"!"),
         icmp_answered=1)
dropped(G, "icmp_over_the_padding",
        "ICMP's checksum covers the message, not the frame's padding: one\n"
        "computed over a padding byte too fails.",
        icmp_from_gw(icmp(8, 0, 0x1234, 1, b"!",
                          check=csum(icmp(8, 0, 0x1234, 1, b"!\x01", check=0)))) + b"\x01",
        "icmp_checksum")

# ---------------------------------------------------------------- held
G = "held"
c = Case(G, "waits_for_an_arp_reply",
         "An echo request from 10.0.2.3, which the cache does not have: the reply\n"
         "waits and a request goes out; the ARP reply sends the waiting packet.")
c.input(echo_request(H3, M3), outs=[arp_request_for(H3)])
c.input(arp_reply_from(H3, M3), outs=[icmp_reply(M3, H3, 1, 0x1234, 1, DATA)])
c.stats(icmp_answered=1, arp_learnt=1)

c = Case(G, "released_by_an_arp_request",
         "The host's own request for the stack resolves it too: the ARP reply, then\n"
         "the waiting packet.")
c.input(datagram(b"wait", src=H3, mac=M3), outs=[arp_request_for(H3)])
c.input(arp_request_from(H3, M3),
        outs=[arp_reply_to(M3, H3), udp_echo(M3, H3, 1, 40000, b"wait")])
c.stats(udp_received=1, arp_answered=1)

c = Case(G, "a_later_packet_replaces_it",
         "A second packet to a pending address replaces the waiting one and asks\n"
         "again: each new packet is the retry.")
c.input(datagram(b"first", src=H3, mac=M3), outs=[arp_request_for(H3)])
c.input(datagram(b"second", src=H3, mac=M3), outs=[arp_request_for(H3)])
c.input(arp_reply_from(H3, M3), outs=[udp_echo(M3, H3, 2, 40000, b"second")])
c.stats(udp_received=2, arp_learnt=1, held_replaced=1)

c = Case(G, "four_wait_at_most",
         "Four packets wait, for 10.0.2.3 to 10.0.2.6; a fifth, for 10.0.2.7, is\n"
         "dropped, though its request still goes out. Each reply then sends its\n"
         "host's packet; 10.0.2.7's sends nothing.")
for n in range(3, 8):
    h, m = host(n)
    c.input(datagram(b"wait", src=h, mac=m, sport=40000 + n), outs=[arp_request_for(h)])
for n in range(3, 8):
    h, m = host(n)
    outs = [udp_echo(m, h, n - 2, 40000 + n, b"wait")] if n < 7 else []
    c.input(arp_reply_from(h, m), outs=outs)
c.stats(udp_received=5, arp_learnt=5, held_full=1)

c = Case(G, "lost_with_its_entry",
         "10.0.2.3's packet waits in its pending entry; eight more hosts are learnt,\n"
         "and the eighth replaces the least recently used entry, 10.0.2.3's, with\n"
         "its packet. 10.0.2.3's reply is then learnt and sends nothing.")
c.input(datagram(b"wait", src=H3, mac=M3), outs=[arp_request_for(H3)])
for n in range(4, 12):
    h, m = host(n)
    c.input(arp_request_from(h, m), outs=[arp_reply_to(m, h)])
c.input(arp_reply_from(H3, M3))
c.stats(udp_received=1, arp_answered=8, arp_learnt=1, held_evicted=1)

c = Case(G, "no_buffer_when_it_resolves",
         "The waiting packet is dropped, and counted, if no transmit buffer is\n"
         "free when its address resolves; it does not wait again.")
c.input(echo_request(H3, M3), outs=[arp_request_for(H3)])
c.tx(0)
c.input(arp_reply_from(H3, M3))
c.tx("any")
c.input(arp_reply_from(H3, M3))
c.stats(icmp_answered=1, arp_learnt=2, tx_full=1)

c = Case(G, "three_frames_for_one_input",
         "After Stack::start an echo reply to 192.0.2.7 waits for the gateway; the\n"
         "gateway's request for the stack then sends three frames: the ARP reply,\n"
         "the waiting packet and the stack's echo request.")
c.start(outs=[arp_request_for(GW)])
c.input(echo_request(ip("192.0.2.7"), GWMAC), outs=[arp_request_for(GW)])
c.input(arp_request_from(GW, GWMAC),
        outs=[arp_reply_to(GWMAC, GW), icmp_reply(GWMAC, ip("192.0.2.7"), 1, 0x1234, 1, DATA),
              ping(2)],
        events=[GATEWAY_EVENT])
c.stats(icmp_answered=1, arp_answered=1)

c = Case(G, "beyond_the_gateway_waits",
         "Without the gateway's MAC an echo to 198.51.100.9 waits for the gateway.")
c.input(datagram(b"far", src=ip("198.51.100.9")), outs=[arp_request_for(GW)])
c.input(gateway_reply(), outs=[udp_echo(GWMAC, ip("198.51.100.9"), 1, 40000, b"far")],
        events=[GATEWAY_EVENT])
c.stats(udp_received=1, arp_learnt=1)

c = Case(G, "the_identification_is_taken_when_built",
         "A packet takes its identification when it is built: the waiting one keeps\n"
         "1, and the echo built after it, to a resolved host, takes 2.")
c.input(echo_request(H3, M3), outs=[arp_request_for(H3)])
c.input(gateway_reply(), events=[GATEWAY_EVENT])
c.input(echo_request(), outs=[icmp_reply(GWMAC, GW, 2, 0x1234, 1, DATA)])
c.input(arp_reply_from(H3, M3), outs=[icmp_reply(M3, H3, 1, 0x1234, 1, DATA)])
c.stats(icmp_answered=2, arp_learnt=2)

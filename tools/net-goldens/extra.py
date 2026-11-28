"""The test writer's further net goldens, with the same library (lib.py):
python3 -I tools/net-goldens/extra.py <user/net/golden>, after gen.py.
Adds cases; removes nothing."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa: E402
from lib import *  # noqa: E402,F401,F403

lib.ROOT = sys.argv[1]
assert os.path.isdir(lib.ROOT)

H3, M3 = host(3)
H4, M4 = host(4)
FAR = ip("93.184.216.34")
FAR_MAC = bytes([2, 0, 0, 0, 0, 0x77])
M3b = bytes([2, 0, 0, 0, 0, 0x33])
DATA = b"abcdefghijklmnop"

G = "arp"

# "Learning: RFC 826's merge: a sender already in the cache is updated by
# any ARP packet": a reply, not only a request, for another address.
c = Case(G, "reply_for_another_merges",
         "RFC 826's merge: a known sender's reply to another address moves it to\n"
         "a new MAC, as a request for another address does; it is not answered.")
c.input(arp_request_from(H3, M3), outs=[arp_reply_to(M3, H3)])
c.input(arp_reply_from(H3, M3b, tpa=H4, tha=M4, dst=BC))
c.input(echo_request(H3, M3b), outs=[icmp_reply(M3b, H3, 1, 0x1234, 1, DATA)])
c.stats(arp_answered=1, arp_not_ours=1, icmp_answered=1)

# "Requests for our address: answered with a reply to the sender", whatever
# its address; "Next hop": packets to it go through the gateway all the same.
c = Case(G, "request_from_beyond_the_subnet_answered",
         "An ARP request for the stack from an address outside its subnet is\n"
         "answered to its sender on the link, and the sender learnt; an echo\n"
         "request from that address is answered through the gateway, which the\n"
         "stack must ask for first.")
c.input(arp_request_from(FAR, FAR_MAC), outs=[arp_reply_to(FAR_MAC, FAR)])
c.input(echo_request(FAR, FAR_MAC), outs=[arp_request_for(GW)])
c.input(gateway_reply(), "the gateway's ARP reply: the waiting echo reply goes",
        outs=[icmp_reply(GWMAC, FAR, 1, 0x1234, 1, DATA)], events=[GATEWAY_EVENT])
c.stats(arp_answered=1, arp_learnt=1, icmp_answered=1)

for p in lib.WRITTEN:
    print("wrote", p)

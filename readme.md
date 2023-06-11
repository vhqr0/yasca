YASCA: Yet Another SCApy
========================

This library is a lightweight replacement of scapy for packet building and parsing.

FEATURE
=======

1. Ether
2. IPv4/IPv6
3. ICMPv4/ICMPv6
4. ARP/NDP
5. TCP/UDP

USAGE
=====

```python
import yasca.all as yc

pkt = yc.Ether(dst='33:33:00:00:00:01') / \
    yc.IPv6(dst='ff02::1') / \
    yc.ICMPv6EchoRequest() / \
    b'hello'

buf = bytes(pkt)

# send(buf)
# buf = recv()

pkt = yc.Ether.parse(buf)

print(repr(pkt))
```

TODO
====

Higher priority first:


1. Rewrite IPv4/TCP Options as Packet
2. IGMP/MLD
3. UDP upper layer protocol
4. DNS/mDNS/LLMNR
5. DHCPv4/DHCPv6

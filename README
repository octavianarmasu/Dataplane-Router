### Copyright Armasu Octavian 325CA

# Dataplane Router

### Introduction
This project serves as an implementation of a router using a dataplane
approach. It builds upon the foundation laid out in Lab4 of the PCOM course.

### Overview
The Dataplane Router is engineered to manage incoming network packets,
identify their intended destinations, and appropriately route them. It employs
routing table queries, manipulation of Internet Protocol (IP) headers, and
Internet Control Message Protocol (ICMP) responses to facilitate effective
packet routing and communication within a network setting.

The router starts by initializing its routing table (rtable) and ARP table
(arp_table) by reading from specified files. These tables are essential
for routing decisions and address resolution. Then I use `qsort` so I can sort
the rtable and I use the function `aux_sort`, which is an auxiliary function
for qsort. It compares two route_table_entry structures. If the prefix of the
first element is greater than the second one or if the prefix is the same and
the mask of the first element is greater than the second one, it returns 1.
Otherwise, it returns -1.

Upon receiving a packet, the router first checks if the destination IP address
in the packet's IP header matches its own IP address. If it does, the router
generates an `ICMP Echo Reply` packet (ICMP type 0) and sends it back to the 
source address of the incoming packet.

If the TTL (Time-to-Live) value in the packet's IP header is less than or equal
to 1, the router generates an `ICMP Time Exceeded` packet (ICMP type 11) and
sends it back to the source address of the incoming packet.

Next, the router performs a lookup in its routing table to find the best route
for the packet's destination IP address. To find the best route I use the
function `get_best_route`, which uses binary search. If no suitable route is
found, the router generates an `ICMP Destination Unreachable` packet (ICMP type 3)
and sends it back to the source address of the incoming packet.

If a valid route is found in the routing table, the router decrements the TTL
in the IP header, updates the IP header checksum using the function
`update_ip_hdr_check`, and forwards the packet to the next hop along the
determined route.

For ICMP handling, the code utilizes the `icmp_response` function. This
function first updates the data in the IP header using `update_iphdr`. Then, it
employs `update_icmphdr` to generate the ICMP header and adjust it with the
appropriate ICMP type (0, 3, or 11). Additionally, the `swap_eth_hdr` function
is utilized to interchange the source and destination addresses in the Ethernet
header. Finally, the function copies the initial 64 bits from the payload of
the original packet and proceeds to transmit the packet.

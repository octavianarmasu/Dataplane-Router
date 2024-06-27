/*
  Copyright Armasu Octavian 325CA
*/
#include "arpa/inet.h"
#include "lib.h"
#include "protocols.h"
#include "queue.h"

/* Route table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

/*
  Auxiliary function for qsort.
  Compares two route_table_entry structures.
  If the prefix of the first element is greater than the second one
  or if the prefix is the same and the mask of the first element is greater
  than the second one, it returns 1.
  Otherwise, it returns -1.
*/
static int aux_sort(const void *table1, const void *table2) {
  struct route_table_entry route1 = *(struct route_table_entry *)table1;
  struct route_table_entry route2 = *(struct route_table_entry *)table2;

  if (ntohl(route1.prefix) > ntohl(route2.prefix) ||
      (ntohl(route1.prefix) == ntohl(route2.prefix) &&
       ntohl(route1.mask) > ntohl(route2.mask)))
    return 1;

  return -1;
}

/*
  Function that takes an IP as a parameter and returns the best route
  from the routing table for that IP.
  Binary search is used for searching.
  If a route with matching prefix and mask is found and it is better than
  the current route, the current route is updated.
*/

struct route_table_entry *get_best_route(uint32_t ip_dest) {
  struct route_table_entry *best_route = NULL;
  int left = 0;
  int right = rtable_len - 1;

  while (left <= right) {
    int mid = left + (right - left) / 2;
    if (best_route == NULL) {
      if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix) {
        best_route = rtable + mid;
      }
    } else {
      if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix &&
          ntohl(rtable[mid].mask) > ntohl(best_route->mask)) {
        best_route = rtable + mid;
      }
    }

    if (ntohl(rtable[mid].prefix) <= ntohl(ip_dest)) {
      left = mid + 1;
    } else {
      right = mid - 1;
    }
  }
  return best_route;
}

/*
  Function that takes an IP as a parameter and returns the best entry
  from the ARP table for that IP.
  Linear search is used.
  If an entry with the matching IP is found, that entry is returned.
  Otherwise, it returns NULL.
*/

struct arp_table_entry *get_best_arp_table(uint32_t ip_dest) {
  for (int i = 0; i < arp_table_len; i++) {
    if (arp_table[i].ip == ip_dest) return (arp_table + i);
  }
  return NULL;
}

/*
  Function to update the IP header checksum.
  It utilizes the checksum function from lib.h.
*/

void update_ip_hdr_check(struct iphdr *ip_hdr) {
  ip_hdr->check = 0;
  ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
}

/*
  The function updates the IP fields in the buffer.
  Source address is updated with the destination address and vice versa.
  The total length of the packet is updated.
  TTL is updated.
  Protocol is updated.
  Checksum is updated.
  It returns the updated IP address.
*/

struct iphdr *update_iphdr(char *buf, uint16_t len, uint32_t ip) {
  struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
  ip_hdr->daddr = ip_hdr->saddr;
  ip_hdr->saddr = ip;
  ip_hdr->tot_len = htons(sizeof(struct icmphdr) + sizeof(struct iphdr) + len);
  ip_hdr->ttl = htons(TTL);
  ip_hdr->protocol = IPPROTO_ICMP;
  update_ip_hdr_check(ip_hdr);

  return ip_hdr;
}

/*
  Function that takes an Ethernet header and a route table entry as parameters.
  It updates the source and destination addresses in the Ethernet header.
  It returns the updated Ethernet header address.
*/

struct ether_header *next_addr(struct ether_header *eth_hdr,
                               struct route_table_entry *best_route) {
  struct arp_table_entry *arp_entry = get_best_arp_table(best_route->next_hop);

  if (arp_entry == NULL) {
    return eth_hdr;
  }

  memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_LEN);
  uint8_t mac[MAC_LEN];
  get_interface_mac(best_route->interface, mac);
  memcpy(eth_hdr->ether_shost, mac, MAC_LEN);

  return eth_hdr;
}

/*
  Function that takes a buffer and a number as parameters.
  It updates the ICMP fields in the buffer.
  ICMP type and code are updated.
  Checksum is updated.
  It changes the ICMP to the desired type.
*/

void update_icmphdr(char *buf, uint8_t num) {
  struct icmphdr *icmp_hdr =
      (struct icmphdr *)(buf + sizeof(struct ether_header) +
                         sizeof(struct iphdr));
  icmp_hdr->type = num;
  icmp_hdr->code = 0;
  icmp_hdr->checksum = 0;
  icmp_hdr->checksum =
      htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
}

/*
  Function that takes an Ethernet header as a parameter.
  It swaps the source and destination addresses in the Ethernet header
  using an auxiliary buffer.
*/

void swap_eth_hdr(struct ether_header *eth_hdr) {
  uint8_t aux[MAC_LEN];
  memcpy(aux, eth_hdr->ether_dhost, MAC_LEN);
  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
  memcpy(eth_hdr->ether_shost, aux, MAC_LEN);
}

/*
  Function that constructs and sends an ICMP packet of type 'num' to the
  'interface' interface.
  It updates the IP header with the new IP address.
  It swaps the source and destination addresses in the Ethernet header.
  It sends the packet to the interface.
*/

void icmp_response(struct ether_header *eth_hdr, uint8_t num,
                   uint32_t interface, char *buf, uint32_t ip) {
  struct iphdr *ip_hdr = update_iphdr(buf, LENGTH, ip);
  update_icmphdr(buf, num);

  swap_eth_hdr(eth_hdr);

  char *new_buf = buf + sizeof(struct ether_header) + sizeof(struct iphdr) +
                  sizeof(struct icmphdr);
  uint32_t total_len = sizeof(struct ether_header) + sizeof(struct iphdr) +
                       sizeof(struct icmphdr) + LENGTH;

  memcpy(new_buf, ip_hdr, LENGTH);
  send_to_link(interface, buf, total_len);
}

int main(int argc, char *argv[]) {
  char buf[MAX_PACKET_LEN];

  // Do not modify this line
  init(argc - 2, argv + 2);

  /*
  Allocate route table and ARP table.
  Read route table and sort it using qsort.
  Read ARP table.
  */
  rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_LEN);
  DIE(rtable == NULL, "malloc failed");
  rtable_len = read_rtable(argv[1], rtable);
  qsort(rtable, rtable_len, sizeof(struct route_table_entry), aux_sort);

  arp_table = malloc(sizeof(struct arp_table_entry) * MAC_LEN);
  DIE(arp_table == NULL, "malloc failed");
  arp_table_len = parse_arp_table("arp_table.txt", arp_table);

  while (1) {
    int interface;
    size_t len;

    interface = recv_from_any_link(buf, &len);
    DIE(interface < 0, "recv_from_any_links");

    struct ether_header *eth_hdr = (struct ether_header *)buf;

    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

    /*
      Obtain the IP using the get_interface_ip and inet_addr functions.
    */
    uint32_t ip = inet_addr(get_interface_ip(interface));

    /*
      If the IP is destined for the router, send an ICMP Echo Reply.
    */
    if (ip == ip_hdr->daddr) {
      icmp_response(eth_hdr, ICMP_ECHO_REPLY, interface, buf, ip);
      continue;
    }

    /*
      Check the IP header checksum.
    */
    if (htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) != 0) {
      continue;
    }

    /*
      Check TTL.
      If TTL is less than or equal to 1, send an ICMP Time Exceeded response.
    */
    if (ip_hdr->ttl <= 1) {
      icmp_response(eth_hdr, ICMP_TTL, interface, buf, ip);
      continue;
    }

    /*
      Get the best route for the destination IP.
      If no route exists, send an ICMP Destination Unreachable response.
    */
    struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
    if (!best_route) {
      icmp_response(eth_hdr, ICMP_UNREACH, interface, buf, ip);
      continue;
    }

    ip_hdr->ttl--;
    update_ip_hdr_check(ip_hdr);

    /*
      Update the source and destination addresses in the Ethernet header.
      Then send the packet.
    */

    eth_hdr = next_addr(eth_hdr, best_route);
    send_to_link(best_route->interface, buf, len);
  }
  free(rtable);
  free(arp_table);
}

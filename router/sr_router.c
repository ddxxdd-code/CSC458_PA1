#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* functio prototypes */
void make_icmp_header(sr_icmp_hdr_t *header, uint8_t type, uint8_t code, unsigned int len);
void make_icmp_t3_header(sr_icmp_t3_hdr_t *header, uint8_t type, uint8_t code, uint8_t *data, unsigned int len);
void make_ip_header(sr_ip_hdr_t *header, uint16_t data_len, uint8_t ttl, uint8_t protocol, uint32_t src, uint32_t dst);
void make_arp_header(sr_arp_hdr_t *header, unsigned short op, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip);
void make_ethernet_header(sr_ethernet_hdr_t *header, uint8_t *dhost, uint8_t *shost, uint16_t type);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  if (len < sizeof(sr_ethernet_hdr_t)) {
    /* length impossible to cover ethernet header, corrupted packet */
    return;
  }
  print_hdrs(packet, len);

  /* get interface */
  printf("incoming interface: %s\n", interface);
  struct sr_if *incoming_interface = sr_get_interface(sr, interface);
  
  /* Try to handle a packet
   parse the ethernet header*/
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
  uint8_t ethernet_destination[ETHER_ADDR_LEN];
  uint8_t ethernet_source[ETHER_ADDR_LEN];
  memcpy(ethernet_destination, ethernet_header->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ethernet_source, ethernet_header->ether_shost, ETHER_ADDR_LEN);
  printf("recorded ethernet addresses source\n");
  print_addr_eth(ethernet_source);
  printf("ethernet destination\n");
  print_addr_eth(ethernet_destination);
  uint16_t ethernet_type = ntohs(ethernet_header->ether_type);
  /*printf("ethernet type: %x\n", ethernet_type);*/
  /* brach on type of packet */
  if (ethernet_type == (uint16_t) ethertype_ip) {
    printf("ip packet\n");
    /* try to parse ip packet */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    if (len - sizeof(sr_ethernet_hdr_t) != ntohs(ip_header->ip_len)) {
      printf("ip length inconsistent with packet length\n");
      return;
    }
    print_hdr_ip((uint8_t *) ip_header);
    uint32_t source_ip = ip_header->ip_src;
    uint32_t target_ip = ip_header->ip_dst;
    /* check if it's for me */
    /* find if destination ip is one of my ports */
    struct sr_if *target_interface = sr_get_interface_by_ip(sr, target_ip);
    if (target_interface != NULL) {
      /* This is for me */
      printf("ip packet for me\n");
      /* Check if it's ICMP */
      if (ip_header->ip_p == (uint8_t) ip_protocol_icmp) {
        printf("icmp for me\n");
        sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        print_hdr_icmp((uint8_t *) icmp_header);
        printf("icmp type: %d\n", icmp_header->icmp_type);
        if (icmp_header->icmp_type == (uint8_t) 8) {
          printf("ICMP echo message\n");
          /* send icmp echo reply*/
          send_icmp(sr, 0, 0, target_ip, source_ip, ((uint8_t *) packet) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t));
        }
      } else {
        /* For other types, return ICMP port unreachable*/
        printf("other type IP packet for me\n");
        send_icmp_t3(sr, 3, 3, target_ip, source_ip, (uint8_t *) ip_header);
      }
    } else {
      /* This is not for me */
      printf("ip packet not for me\n");
      /* sanity check the incoming packet */
      uint16_t check_sum = ip_header->ip_sum;
      ip_header->ip_sum = 0;
      if (len - sizeof(sr_ethernet_hdr_t) < sizeof(sr_ip_hdr_t) 
      || check_sum != cksum(ip_header, sizeof(sr_ip_hdr_t))) {
        /* sanity check failed */
        /* should not do anything here */
        printf("ip packet sanity check failed\n");
        return;
      }
      /* decrease TTL */
      if (ip_header->ip_ttl <= 1) {
        /* TTL <= 1, should send icmp time exceeded */
        /* Send ICMP time exceeded back to source */
        printf("ip packet timeout\n");
        send_icmp_t3(sr, 11, 0, incoming_interface->ip, source_ip, (uint8_t *) ip_header);
        /* this case should go no further*/
        return;
      } else {
        ip_header->ip_ttl -= 1;
      }
      /* update ip header check sum */
      ip_header->ip_sum = 0;
      ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
      /* find best match interface */
      struct sr_rt *target_routing_table = lpm_ip(sr, target_ip);
      if (target_routing_table) {
        /* next hop found */
        struct sr_if *target_out_interface = sr_get_interface(sr, target_routing_table->interface);
        printf("next interface found\n");
        if (!target_out_interface) {
          printf("no interface %s found\n", target_routing_table->interface);
          exit(1);
        }
        sr_arpcache_dump(&sr->cache);
        struct sr_arpentry *target_arpentry = sr_arpcache_lookup(&sr->cache, target_routing_table->gw.s_addr);
        print_addr_ip_int(ntohl(target_routing_table->gw.s_addr));
        if (target_arpentry) {
          /* send frame to next hop */
          /* need to change ethernet header */
          printf("target arp entry for target MAC found\n");
          make_ethernet_header(ethernet_header, target_arpentry->mac, target_out_interface->addr, ethertype_ip);
          print_hdrs(packet, len);
          sr_send_packet(sr, packet, len, target_out_interface->name);
          free(target_arpentry);
        } else {
          /* next hop MAC can't be found in ARP cache */
          /* Send ARP request */
          printf("target arp entry not found\n");
          unsigned char empty_mac[ETHER_ADDR_LEN] = {0};
          make_ethernet_header(ethernet_header, empty_mac, target_out_interface->addr, ethertype_ip);
          struct sr_arpreq *arp_request = sr_arpcache_queuereq(&sr->cache, target_routing_table->gw.s_addr, packet, len, interface);
          printf("ip: %X\n", arp_request->ip);
          if (arp_request != NULL) {
            handle_arpreq(sr, arp_request);
          }
        }
      } else {
        /* no matching entry in the routing table when forwarding an IP packet, return ICMP net unreachable */
        send_icmp_t3(sr, 3, 0, incoming_interface->ip, source_ip, (uint8_t *) ip_header);
      }
    }
  } else if (ethernet_type == (uint16_t) ethertype_arp) {
    printf("arp packet\n");
    /* try to parse arp packet */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
      printf("arp packet too small, drop it\n");
      return;
    }

    /* parse arp header*/
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    print_hdr_arp((uint8_t *) arp_header);

    unsigned short request_type = ntohs(arp_header->ar_op);

    unsigned char sender_mac[ETHER_ADDR_LEN];
    memcpy(sender_mac, arp_header->ar_sha, ETHER_ADDR_LEN);
    unsigned char target_mac[ETHER_ADDR_LEN];
    memcpy(target_mac, arp_header->ar_tha, ETHER_ADDR_LEN);

    uint32_t sender_ip = arp_header->ar_sip;
    uint32_t target_ip = arp_header->ar_tip;

    printf("sender ip: ");
    print_addr_ip_int(ntohl(sender_ip));
    printf("target ip: ");
    print_addr_ip_int(ntohl(target_ip));
    printf("request: %x\n", request_type);
    if (request_type == (unsigned short) arp_op_request) {
      printf("request for me\n");

      /* send ARP reply */
      send_arp_reply(sr, interface, sender_mac, sender_ip);
    } else if (request_type == (unsigned short) arp_op_reply) {
      printf("reply to me\n");
      /* cache it */
      struct sr_arpreq *waiting_arpreq = sr_arpcache_insert(&sr->cache, sender_mac, sender_ip);
      sr_arpcache_dump(&sr->cache);
      if (waiting_arpreq != NULL) {
        /* there is waiting packets on this arp request, send them all */
        printf("waiting arpreq found\n");
        /* send packets in "packets" */
        struct sr_packet *waiting_packet = waiting_arpreq->packets;
        while (waiting_packet != NULL) {
          printf("waiting packet found\n");
          /* update target MAC address, then send the ethernet frame */
          sr_ethernet_hdr_t *packet_ethernet_header = (sr_ethernet_hdr_t *) waiting_packet->buf;
          memcpy(packet_ethernet_header->ether_dhost, sender_mac, ETHER_ADDR_LEN);
          memcpy(packet_ethernet_header->ether_shost, incoming_interface->addr, ETHER_ADDR_LEN);
          sr_send_packet(sr, (uint8_t *) waiting_packet->buf, waiting_packet->len, interface);
          print_hdrs(waiting_packet->buf, waiting_packet->len);
          waiting_packet = waiting_packet->next;
        }
        printf("finished sending waiting packets, destroy arpreq\n");
        sr_arpreq_destroy(&sr->cache, waiting_arpreq);
      }
    }
  }
}/* end sr_ForwardPacket */

/* for convenience, all functions take network order as input for ip*/

/* Helper functions
 * Functions to process different types of messages
 * The hierachy is as follows:
 * Ethernet header + IP header + ICMP
 * Ethernet header + ARP 
 * To send a message, first malloc enough buffer
 * Then set pointer as each type to corresponding parts of the buffer
 * Call the following functions to fill the parts of the buffer
 * Use sr_send_packet to send to the desired outpust.
 * generate icmp message */
void make_icmp_header(sr_icmp_hdr_t *header, uint8_t type, uint8_t code, unsigned int len) {
  assert(header);
  header->icmp_type = type;
  header->icmp_code = code;
  header->icmp_sum = 0;
  header->icmp_sum = cksum(header, len);
}
/* construct icmp type3 message */
void make_icmp_t3_header(sr_icmp_t3_hdr_t *header, uint8_t type, uint8_t code, uint8_t *data, unsigned int len) {
  assert(header);
  header->icmp_type = type;
  header->icmp_code = code;
  header->next_mtu = htons(1500);
  header->icmp_sum = 0;
  memcpy(header->data, data, ICMP_DATA_SIZE);
  header->icmp_sum = cksum(header, len);
}
/* generate ip header */
void make_ip_header(sr_ip_hdr_t *header, uint16_t data_len, uint8_t ttl, uint8_t protocol, uint32_t src, uint32_t dst) {
  assert(header);
  header->ip_v = 4;
  header->ip_hl = 5;
  header->ip_tos = 0;
  header->ip_len = htons(sizeof(sr_ip_hdr_t) + data_len);
  header->ip_id = htons(1211);
  header->ip_off = htons(IP_DF);
  header->ip_ttl = ttl;
  header->ip_p = protocol;
  header->ip_src = htonl(src);
  header->ip_dst = htonl(dst);
  header->ip_sum = 0x0000;
  header->ip_sum = cksum(header, sizeof(sr_ip_hdr_t));
}
/* populate arp header*/
/* ips in network order*/
void make_arp_header(sr_arp_hdr_t *header, unsigned short op, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip) {
  assert(header);
  header->ar_hrd = htons(arp_hrd_ethernet);
  header->ar_pro = htons(ethertype_ip);
  header->ar_hln = ETHER_ADDR_LEN;
  header->ar_pln = sizeof(uint32_t);
  header->ar_op = htons(op);
  memcpy(header->ar_sha, sha, ETHER_ADDR_LEN);
  header->ar_sip = sip;
  memcpy(header->ar_tha, tha, ETHER_ADDR_LEN);
  header->ar_tip = tip;
}
/* generate ethernet header */
void make_ethernet_header(sr_ethernet_hdr_t *header, uint8_t *dhost, uint8_t *shost, uint16_t type) {
  assert(header);
  memcpy(header->ether_dhost, dhost, ETHER_ADDR_LEN);
  memcpy(header->ether_shost, shost, ETHER_ADDR_LEN);
  header->ether_type = htons(type);
}
/* send icmp message like icmp echo reply */
/* send icmp with payload of length len from source to target ip*/
void send_icmp(struct sr_instance *sr, uint8_t type, uint8_t code, uint32_t source_ip, uint32_t target_ip, uint8_t *payload, unsigned int len) {
  printf("icmp reply\n");
  int length = len + sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
  uint8_t *message = calloc(length, sizeof(uint8_t));
  if (!message) {
    printf("send icmp: malloc error when constructing icmp message\n");
    exit(1);
  }
  /* append payload*/
  memcpy(message + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), payload, len);
  /* populate icmp header*/
  int icmp_length = len + sizeof(sr_icmp_hdr_t);
  sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (message + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_header->icmp_type = type;
  icmp_header->icmp_code = code;
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header, icmp_length);
  /* populate ip header*/
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (message + sizeof(sr_ethernet_hdr_t));
  ip_header->ip_v = 4;
  ip_header->ip_hl = 5;
  ip_header->ip_tos = 0;
  ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_length);
  ip_header->ip_id = htons(1211);
  ip_header->ip_off = htons(IP_DF);
  ip_header->ip_ttl = INIT_TTL;
  ip_header->ip_p = ip_protocol_icmp;
  ip_header->ip_src = source_ip;
  ip_header->ip_dst = target_ip;
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  /* find output interface for target ip destination*/
  struct sr_rt *lpm_rt_entry = lpm_ip(sr, target_ip);
  if (!lpm_rt_entry) {
    printf("send icmp: routing table hop not found\n");
    exit(1);
  }
  struct sr_if *out_interface = sr_get_interface(sr, lpm_rt_entry->interface);
  if (!out_interface) {
    printf("send icmp: out interface not found from its name\n");
    exit(1);
  }
  /* populate ethernet header*/
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) message;
  memcpy(ethernet_header->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
  ethernet_header->ether_type = htons(ethertype_ip);
  /* lookup arpcache for destination MAC*/
  /* look up next hop MAC by ip*/
  struct sr_arpentry *target_arpentry = sr_arpcache_lookup(&sr->cache, target_ip);
  if (target_arpentry) {
      memcpy(ethernet_header->ether_dhost, target_arpentry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, message, length, out_interface->name);
      free(target_arpentry);
      print_hdrs(message, length);
  } else {
      printf("send icmp: no arp cache found for the ip, cache out packet to arpcache");
      struct sr_arpreq *waiting_arpreq = sr_arpcache_queuereq(&sr->cache, target_ip, message, length, out_interface->name);
      handle_arpreq(sr, waiting_arpreq);
  }
  free(message);
}
/* send icmp type 3 message */
void send_icmp_t3(struct sr_instance *sr, uint8_t type, uint8_t code, uint32_t source_ip, uint32_t target_ip, uint8_t *incoming_ip_header) {
  printf("icmp t3 message\n");
  int length = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
  uint8_t *message = calloc(length, sizeof(uint8_t));
  if (!message) {
    printf("send icmp t3: malloc error when constructing icmp message\n");
    exit(1);
  }
  /* populate icmp header*/
  int icmp_length = sizeof(sr_icmp_t3_hdr_t);
  sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *) (message + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  memcpy(icmp_header->data, incoming_ip_header, ICMP_DATA_SIZE);
  icmp_header->icmp_type = type;
  icmp_header->icmp_code = code;
  icmp_header->unused = 0;
  icmp_header->next_mtu = htons(1500);
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header, icmp_length);
  /* populate ip header*/
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (message + sizeof(sr_ethernet_hdr_t));
  ip_header->ip_v = 4;
  ip_header->ip_hl = 5;
  ip_header->ip_tos = 0;
  ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_length);
  ip_header->ip_id = htons(1211);
  ip_header->ip_off = htons(IP_DF);
  ip_header->ip_ttl = INIT_TTL;
  ip_header->ip_p = ip_protocol_icmp;
  ip_header->ip_src = source_ip;
  ip_header->ip_dst = target_ip;
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  /* find output interface for target ip destination*/
  struct sr_rt *lpm_rt_entry = lpm_ip(sr, target_ip);
  if (!lpm_rt_entry) {
    printf("send icmp t3: routing table hop not found\n");
    exit(1);
  }
  struct sr_if *out_interface = sr_get_interface(sr, lpm_rt_entry->interface);
  if (!out_interface) {
    printf("send icmp t3: out interface not found from its name\n");
    exit(1);
  }
  /* populate ethernet header*/
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) message;
  memcpy(ethernet_header->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
  ethernet_header->ether_type = htons(ethertype_ip);
  /* lookup arpcache for destination MAC*/
  /* look up next hop MAC by ip*/
  struct sr_arpentry *target_arpentry = sr_arpcache_lookup(&sr->cache, target_ip);
  if (target_arpentry) {
      memcpy(ethernet_header->ether_dhost, target_arpentry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, message, length, out_interface->name);
      free(target_arpentry);
      print_hdrs(message, length);
  } else {
      printf("send icmp t3: no arp cache found for the ip, cache out packet to arpcache");
      struct sr_arpreq *waiting_arpreq = sr_arpcache_queuereq(&sr->cache, target_ip, message, length, out_interface->name);
      handle_arpreq(sr, waiting_arpreq);
  }
  free(message);
}
/* send ARP reply message */
void send_arp_reply(struct sr_instance *sr, char *interface, unsigned char *tha, uint32_t tip) {
  struct sr_if *out_interface = sr_get_interface(sr, interface);
  if (!out_interface) {
    printf("arp reply: interface %s not found\n", interface);
    exit(1);
  }
  /* construct message*/
  int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *message = calloc(length, sizeof(uint8_t));
  if (!message) {
    printf("arp reply: making arp message: malloc error\n");
    exit(1);
  }
  /* make arp header*/
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (message + sizeof(sr_ethernet_hdr_t));
  arp_header->ar_hrd = htons(arp_hrd_ethernet);
  arp_header->ar_pro = htons(ethertype_ip);
  arp_header->ar_hln = ETHER_ADDR_LEN;
  arp_header->ar_pln = sizeof(uint32_t);
  arp_header->ar_op = htons(arp_op_reply);
  memcpy(arp_header->ar_sha, out_interface->addr, ETHER_ADDR_LEN);
  arp_header->ar_sip = out_interface->ip;
  memcpy(arp_header->ar_tha, tha, ETHER_ADDR_LEN);
  arp_header->ar_tip = tip;
  /* make ethernet header*/
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) message;
  memcpy(ethernet_header->ether_dhost, tha, ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
  ethernet_header->ether_type = htons(ethertype_arp);
  /* send from interface*/
  sr_send_packet(sr, message, length, interface);
  printf("arp reply\n");
  print_hdrs(message, length);
  free(message);
}
/* send ARP request broadcasting message */
void send_arp_request(struct sr_instance *sr, char *interface, uint32_t tip) {
  struct sr_if *out_interface = sr_get_interface(sr, interface);
  if (!out_interface) {
    printf("arp request: interface %s not found\n", interface);
    exit(1);
  }
  /* construct message*/
  int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *message = calloc(length, sizeof(uint8_t));
  if (!message) {
    printf("arp request: making arp message: malloc error\n");
    exit(1);
  }
  /* make arp header*/
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (message + sizeof(sr_ethernet_hdr_t));
  arp_header->ar_hrd = htons(arp_hrd_ethernet);
  arp_header->ar_pro = htons(ethertype_ip);
  arp_header->ar_hln = ETHER_ADDR_LEN;
  arp_header->ar_pln = sizeof(uint32_t);
  arp_header->ar_op = htons(arp_op_request);
  memcpy(arp_header->ar_sha, out_interface->addr, ETHER_ADDR_LEN);
  arp_header->ar_sip = out_interface->ip;
  uint8_t empty_mac[ETHER_ADDR_LEN] = {0};
  memcpy(arp_header->ar_tha, empty_mac, ETHER_ADDR_LEN);
  arp_header->ar_tip = tip;
  /* make ethernet header*/
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) message;
  uint8_t broadcast_mac[ETHER_ADDR_LEN];
  int i;
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    broadcast_mac[i] = 255;
  }
  memcpy(ethernet_header->ether_dhost, broadcast_mac, ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
  ethernet_header->ether_type = htons(ethertype_arp);
  /* send from interface*/
  sr_send_packet(sr, message, length, interface);
  printf("arp request\n");
  print_hdrs(message, length);
  free(message);
}
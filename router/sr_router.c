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
void make_icmp_header(sr_icmp_hdr_t *header, uint8_t type, uint8_t code);
void make_icmp_t3_header(sr_icmp_t3_hdr_t *header, uint8_t type, uint8_t code, uint8_t *data, int len);
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
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (ethernet_header + sizeof(sr_ethernet_hdr_t));
    /* TODO: handle ip packet */
  } else if (ethernet_type == (uint16_t) ethertype_arp) {
    printf("arp packet\n");
    /* try to parse arp packet */
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (ethernet_header + sizeof(sr_ethernet_hdr_t));
    /*print_hdr_arp(arp_header);*/
    unsigned short request_type = ntohs(arp_header->ar_op);
    unsigned char sender_mac[ETHER_ADDR_LEN];
    memcpy(sender_mac, arp_header->ar_sha, ETHER_ADDR_LEN);
    unsigned char target_mac[ETHER_ADDR_LEN];
    memcpy(target_mac, arp_header->ar_tha, ETHER_ADDR_LEN);
    uint32_t sender_ip = ntohl(arp_header->ar_sip);
    uint32_t target_ip = ntohl(arp_header->ar_tip);
    /*printf("sender ip: ");
    print_addr_ip_int(arp_header->ar_sip);
    printf("target ip: ");
    print_addr_ip_int(arp_header->ar_tip);
    printf("request: %x\n", request_type);*/
    if (request_type == (unsigned short) arp_op_request) {
      printf("request for me\n");
      /* construct ARP reply */
      /* get interface */
      printf("incoming interface: %s\n", interface);
      struct sr_if *incoming_interface = sr_get_interface(sr, interface);
      unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      uint8_t *packet = malloc(length);
      if (packet == NULL) {
        printf("malloc in sr_router arp reply failed\n");
        exit(1);
      }
      sr_arp_hdr_t *arp_reply_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
      /* printf("interface ip: %x\n", incoming_interface->ip); */
      make_arp_header(arp_reply_header, arp_op_reply, incoming_interface->addr, ntohl(incoming_interface->ip), sender_mac, sender_ip);
      make_ethernet_header((sr_ethernet_hdr_t *) packet, ethernet_source, incoming_interface->addr, ethertype_arp);
      /* print_hdr_arp((sr_ethernet_hdr_t *) arp_reply_header); */
      sr_send_packet(sr, packet, length, interface);
      free(packet);
    } else if (request_type == (unsigned short) arp_op_reply) {
      printf("reply to me\n");
      /* cache it */
      struct sr_arpreq *waiting_arpreq = sr_arpcache_insert(&sr->cache, sender_mac, sender_ip);
      if (waiting_arpreq != NULL) {
        /* there is waiting arp request, send them all */
        /* send packets in "packets" */
        struct sr_packet *waiting_packet = waiting_arpreq->packets;
        while (waiting_packet != NULL) {
          /* update target MAC address, then send the ethernet frame */
          sr_ethernet_hdr_t *packet_ethernet_header = (sr_ethernet_hdr_t *) waiting_packet->buf;
          memcpy(packet_ethernet_header->ether_dhost, &sender_mac, ETHER_ADDR_LEN);
          sr_send_packet(sr, (uint8_t *) waiting_packet->buf, waiting_packet->len, waiting_packet->iface);

          waiting_packet = waiting_packet->next;
        }
        sr_arpreq_destroy(&sr->cache, waiting_arpreq);
      }
    }

  }
  
}/* end sr_ForwardPacket */

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
void make_icmp_header(sr_icmp_hdr_t *header, uint8_t type, uint8_t code) {
  assert(header);
  header->icmp_type = type;
  header->icmp_code = code;
  header->icmp_sum = htons(cksum(header, 2));
}
/* construct icmp type3 message */
void make_icmp_t3_header(sr_icmp_t3_hdr_t *header, uint8_t type, uint8_t code, uint8_t *data, int len) {
  assert(header);
  header->icmp_type = type;
  header->icmp_code = code;
  header->icmp_sum = htons(cksum(header, 2));
  memcpy(header->data, data, ICMP_DATA_SIZE);
}
/* generate ip header */
void make_ip_header(sr_ip_hdr_t *header, uint16_t data_len, uint8_t ttl, uint8_t protocol, uint32_t src, uint32_t dst) {
  assert(header);
  header->ip_len = htons(sizeof(sr_ip_hdr_t) + data_len);
  header->ip_ttl = ttl;
  header->ip_p = protocol;
  header->ip_src = src;
  header->ip_dst = dst;
  header->ip_sum = 0x0000;
  header->ip_sum = htons(cksum(header, sizeof(sr_ip_hdr_t) - 2 * sizeof(uint32_t)));
}
/* generate arp */
void make_arp_header(sr_arp_hdr_t *header, unsigned short op, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip) {
  assert(header);
  header->ar_hrd = htons(arp_hrd_ethernet);
  header->ar_pro = htons(ethertype_ip);
  header->ar_hln = ETHER_ADDR_LEN;
  header->ar_pln = sizeof(uint32_t);
  header->ar_op = htons(op);
  memcpy(header->ar_sha, sha, ETHER_ADDR_LEN);
  header->ar_sip = htonl(sip);
  memcpy(header->ar_tha, tha, ETHER_ADDR_LEN);
  header->ar_tip = htonl(tip);
}
/* generate ethernet header */
void make_ethernet_header(sr_ethernet_hdr_t *header, uint8_t *dhost, uint8_t *shost, uint16_t type) {
  assert(header);
  memcpy(header->ether_dhost, dhost, ETHER_ADDR_LEN);
  memcpy(header->ether_shost, shost, ETHER_ADDR_LEN);
  header->ether_type = htons(type);
}

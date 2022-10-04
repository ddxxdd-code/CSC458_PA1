#include <stdio.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
  // Try to handle a packet
  // parse the ethernet header
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
  uint8_t ethernet_destination[ETHER_ADDR_LEN];
  uint8_t ethernet_source[ETHER_ADDR_LEN];
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    ethernet_destination[i] = ethernet_header->ether_dhost[i];
    ethernet_source[i] = ethernet_header->ether_shost[i];
  }
  uint8_t ethernet_type = ntohs(ethernet_header->ether_type);
  // brach on type of packet
  if (ethernet_type == ethertype_ip) {
    printf("ip packet");
    // try to parse ip packet
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (ethernet_header + sizeof(sr_ethernet_hdr_t));
  } else if (ethernet_type == ethertype_arp) {
    printf("arp packet");
    // try to parse arp packet
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (ethernet_header + sizeof(sr_ethernet_hdr_t));
  }
  
}/* end sr_ForwardPacket */

// Helper functions
// Functions to process different types of messages
// The hierachy is as follows:
// Ethernet header + IP header + ICMP
// Ethernet header + ARP 
// To send a message, first malloc enough buffer
// Then set pointer as each type to corresponding parts of the buffer
// Call the following functions to fill the parts of the buffer
// Use sr_send_packet to send to the desired outpust.
// generate icmp message
void make_icmp_header(sr_icmp_hdr_t *header, uint8_t type, uint8_t code) {
  assert(header);
  header->icmp_type = type;
  header->icmp_code = code;
  header->icmp_sum = htons(cksum(header, 2));
}
// construct icmp type3 message
void make_icmp_t3_header(sr_icmp_t3_hdr_t *header, uint8_t type, uint8_t code, uint8_t *data, int len) {
  assert(header);
  header->icmp_type = type;
  header->icmp_code = code;
  header->icmp_sum = htons(cksum(header, 2));
  memcpy(header->data, data, ICMP_DATA_SIZE);
}
// generate ip header
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
// generate arp
void make_arp_header(sr_arp_hdr_t *header, unsigned short hrd, unsigned short pro, unsigned short op, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip) {
  assert(header);
  header->ar_hrd = htons(hrd);
  header->ar_pro = htons(pro);
  header->ar_hln = ETHER_ADDR_LEN;
  header->ar_pln = sizeof(uint32_t);
  header->ar_op = op;
  memcpy(header->ar_sha, sha, ETHER_ADDR_LEN);
  header->ar_sip = sip;
  memcpy(header->ar_tha, tha, ETHER_ADDR_LEN);
  header->ar_tip = tip;
}
// generate ethernet header
void make_ethernet_header(sr_ethernet_hdr_t *header, uint8_t *dhost, uint8_t *shost, uint16_t type) {
  assert(header);
  memcpy(header->ether_dhost, dhost, ETHER_ADDR_LEN);
  memcpy(header->ether_shost, shost, ETHER_ADDR_LEN);
  header->ether_type = htons(type);
}

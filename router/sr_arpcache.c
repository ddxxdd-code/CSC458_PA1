#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Loop through the ARP request queue */
    if (sr == NULL) {
        /* sr is empty, can't do anything */
        return;
    }
    /* ARP requests is a linked list in ARP cache. */
    /* Here, notice that handle_arpreq might destroy the request*/
    /* so to keep iteration, we need to move curr to next first */
    struct sr_arpreq *curr = sr->cache.requests;
    struct sr_arpreq *temp = NULL;
    while (curr != NULL) {
        temp = curr;
        curr = curr->next;
        handle_arpreq(sr, temp);
    }
}

/*
    Handle ARP requests
*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request) {
    printf("handle arpreq\n");
    /* Loop each arp request entry */
    printf("ip: %X\n", request->ip);
    if (time(NULL) - request->sent > 1.0) {
        printf("time out\n");
        if (request->times_sent >= 5) {
            printf("repeated to send 5 times, icmp host unreachable\n");
            /* Send icmp host unreachable to source addr 
                * who has sent packet to wait on this arp request. */
            struct sr_packet *curr_packet = request->packets;
            while (curr_packet != NULL) {
                /* Construct icmp unreachable reply and send */
                /* need my MAC, ip, receiver MAC, ip */
                /* packet gives the sender's ip, so can send directly. */
                /* buf is the packet received that waits here, so it contains the sender onformation */
                /* target ip is where I, the router receives the packet */
                /* use target ip to look for out port and next hop mac */
                /* can we assume the packet is ip packet? */
                printf("send current packet:\n");
                print_hdrs(curr_packet->buf, curr_packet->len);
                uint32_t source_ip = ((sr_ip_hdr_t *) (curr_packet->buf + sizeof(sr_ethernet_hdr_t)))->ip_src;
                printf("packet source ip:\n");
                print_addr_ip_int(ntohl(source_ip));
                struct sr_if *out_interface = sr_get_interface_by_ip(sr, source_ip);
                if (out_interface) {
                    /* look for target MAC */
                    unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                    uint8_t *buffer = malloc(length);
                    sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *) (buffer + length - sizeof(sr_icmp_t3_hdr_t));
                    make_icmp_t3_header(icmp_header, 3, 1, curr_packet->buf, sizeof(sr_icmp_t3_hdr_t));
                    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (buffer + sizeof(sr_ethernet_hdr_t));
                    /* perform lpm to find the next hop */
                    struct sr_rt *out_route = perform_lpm_ip(sr, source_ip);
                    if (out_route) {
                        /* find out interface based on next hop */
                        struct sr_if *out_interface = sr_get_interface(sr, out_route->interface);
                        uint32_t next_hop_ip = out_route->gw.s_addr;
                        make_ip_header(ip_header, sizeof(sr_icmp_t3_hdr_t), INIT_TTL, ip_protocol_icmp, ntohl(out_interface->ip), ntohl(next_hop_ip));
                        sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) buffer;
                        uint8_t empty_mac[ETHER_ADDR_LEN] = {0};
                        make_ethernet_header(ethernet_header, empty_mac, out_interface->addr, ethertype_ip);
                        /* look up next hop MAC by ip*/
                        struct sr_arpentry *target_arpentry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
                        if (target_arpentry) {
                            memcpy(ethernet_header->ether_dhost, target_arpentry->mac, ETHER_ADDR_LEN);
                            sr_send_packet(sr, buffer, length, out_interface->name);
                            print_hdrs(buffer, length);
                        } else {
                            struct sr_arpreq *waiting_arpreq = sr_arpcache_queuereq(&sr->cache, next_hop_ip, buffer, length, out_interface->name);
                            handle_arpreq(sr, waiting_arpreq);
                        }
                    }
                    free(buffer);
                }
                curr_packet = curr_packet->next;
            }
            /* Destroy the arpreq entry */
            sr_arpreq_destroy(&sr->cache, request);
        } else {
            /* Send ARP request */
            printf("send ARP request\n");
            /* first locate out post interface */
            printf("target ip:\n");
            print_addr_ip_int(ntohl(request->ip));
            sr_print_if_list(sr);
            /* send request from all interface out and broadcast message */
            struct sr_if *out_interface = sr->if_list;
            while (out_interface != NULL) {
                /* construct ARP request */
                printf("out interface found, construct ARP request\n");
                unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
                uint8_t *arp_request = malloc(length);
                sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (arp_request + sizeof(sr_ethernet_hdr_t));
                unsigned char empty_mac[ETHER_ADDR_LEN] = {0};
                make_arp_header(arp_header, arp_op_request, out_interface->addr, ntohl(out_interface->ip), empty_mac, ntohl(request->ip));
                printf("made arp header\n");
                sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) arp_request;
                uint8_t broadcast_mac[ETHER_ADDR_LEN];
                int i;
                for (i = 0; i < ETHER_ADDR_LEN; i++) {
                    broadcast_mac[i] = 255;
                }
                make_ethernet_header(ethernet_header, broadcast_mac, out_interface->addr, (uint16_t) ethertype_arp);
                printf("made ethernet header\n");
                print_hdrs(arp_request, length);
                sr_send_packet(sr, arp_request, length, out_interface->name);
                free(arp_request);
                out_interface = out_interface->next;
            }
            request->sent = time(NULL);
            request->times_sent++;
        }
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}


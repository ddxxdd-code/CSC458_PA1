#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask,char* if_name)
{
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);

        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);

} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("Destination\tGateway\t\tMask\tIface\n");

    rt_walker = sr->routing_table;
    
    sr_print_routing_entry(rt_walker);
    while(rt_walker->next)
    {
        rt_walker = rt_walker->next; 
        sr_print_routing_entry(rt_walker);
    }

} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    printf("%s\t\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\n",entry->interface);
    /* print_addr_ip_int(ntohl(entry->gw.s_addr)); */

} /* -- sr_print_routing_entry -- */

/*---------------------------------------------------------------------
 * Method: find maximum match prefix
 *
 * 
 *---------------------------------------------------------------------*/
int matched_bits(uint32_t first_ip, uint32_t second_ip, uint32_t mask) {
    uint32_t tester = 1 << 31;
    int count = 0;
    uint32_t masked_first_ip = first_ip & mask;
    uint32_t masked_second_ip = second_ip & mask;
    uint32_t matched_bits = masked_first_ip ^ masked_second_ip;
    int i;
    for (i = 0; i < 32; i++) {
        if (tester & matched_bits) {
            break;
        }
        count++;
        tester >>= 1;
    }
    return count;
} /* -- matched_bits -- */
/*---------------------------------------------------------------------
 * Method: perform_lpm_ip
 *
 * Perform lpm matching to find the best match routing table entry
 * which gives the next hop ip and interface name, 
 * which can then be used to construct headers
 *---------------------------------------------------------------------*/
struct sr_rt *perform_lpm_ip(struct sr_instance *sr, uint32_t target_ip) {
    struct sr_rt *curr = sr->routing_table;
    struct sr_rt *best_match = NULL;
    int max_fit = 0;
    int current_fit = 0;
    while (curr) {
        current_fit = matched_bits(ntohl(curr->dest.s_addr), target_ip, ntohl(curr->mask.s_addr));
        if (current_fit > max_fit) {
            max_fit = current_fit;
            best_match = curr;
        }
        curr = curr->next;
    }
    return best_match;
 } /* -- perform_lpm_ip -- */
/*---------------------------------------------------------------------
 * Method: lpm_ip
 *
 * Perform lpm matching to find the best match routing table entry
 * which gives the next hop ip and interface name, 
 * which can then be used to construct headers
 * Notice: here target_ip in network order
 *---------------------------------------------------------------------*/
struct sr_rt *lpm_ip(struct sr_instance *sr, uint32_t target_ip) {
    struct sr_rt *curr = sr->routing_table;
    struct sr_rt *best_match = NULL;
    uint32_t longest_mask = 0;
    while (curr) {
        uint32_t masked_target_ip = target_ip & curr->mask.s_addr;
        if (masked_target_ip == curr->dest.s_addr) {
            /* prefix match happened*/
            /* save the one with larger mask*/
            if (ntohl(curr->mask.s_addr) > longest_mask) {
                longest_mask = ntohl(curr->mask.s_addr);
                best_match = curr;
            }
        }
        curr = curr->next;
    }
    return best_match;
 } /* -- lpm_ip -- */
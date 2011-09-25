//
//  dns.h
//  kernet
//
//  Created by Mike Chen on 9/13/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef DNS_H
#define DNS_H

struct dns_packet {
    mbuf_t pkt;
    u_int32_t matches_gfw_fingerprint : 1;
    u_int32_t processed : 1;
    u_int32_t modified : 1;
    u_int32_t unused : 29;
    char domain_name[256];
    u_int32_t resolved_ips[4];   /* make lives easier by limiting it to 4 */
};

struct gfw_domain {
    char *domain; 
    TAILQ_ENTRY(gfw_domain) link;
};

__private_extern__ lck_rw_t gGFWDomainListLock;

void kn_dns_initialize();
struct dns_packet* kn_dns_alloc_packet();
void kn_dns_free_packet(struct dns_packet* dnsp);
void kn_dns_dissect_packet(mbuf_t data, struct dns_packet *dnsp);
errno_t kn_dns_check_domain_gfwed(const char *domain);
void kn_dns_close();

#endif

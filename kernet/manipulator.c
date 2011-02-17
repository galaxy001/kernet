/*
 *  scholarzhang.c
 *  kernet
 *
 *  Created by Mike Chen on 2/13/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <sys/systm.h>

#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <netinet/kpi_ipfilter.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>
#include <net/kpi_interface.h>
#include <sys/kpi_socketfilter.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/debug.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>
#include <sys/kern_control.h>
#include <sys/kauth.h>
#include <sys/time.h>
#include <stdarg.h>
#include <sys/queue.h>

#include "kernet.h"

errno_t kn_inject_after_synack (mbuf_t incm_data)
{
	errno_t retval = 0;
	u_int32_t saddr;
	u_int32_t daddr;
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t ack;
	u_int32_t seq;
	struct ip* iph;
	struct tcphdr* tcph;
	
	iph = (struct ip*)mbuf_data(incm_data);
	saddr = iph->ip_dst.s_addr;
	daddr = iph->ip_src.s_addr;
	
	tcph = (struct tcphdr*)((char*)iph + iph->ip_hl * 4);
	sport = tcph->th_dport;
	dport = tcph->th_sport;
	
	/* 
	 * first packet:
	 * 
	 * RST
	 *
	 * SEQ: SEQ in >>>SYN>>>, a.k.a. ACK in <<<SYN+ACK<<< -1
	 * ACK: SEQ in <<<SYN+ACK<<<
	 *
	 */
	
	seq = htonl(ntohl(tcph->th_ack) - 1);
	ack = tcph->th_seq;
	
	retval = kn_inject_tcp_from_params(TH_RST, saddr, daddr, sport, dport, seq, ack, NULL, 0);
	if (retval != 0) {
		return retval;
	}
	
	/* 
	 * second packet:
	 * 
	 * ACK
	 *
	 * SEQ: ACK in <<<SYN+ACK<<<
	 * ACK: SEQ in <<<SYN+ACK<<<
	 *
	 */
	seq = tcph->th_ack;
	ack = tcph->th_seq;
	
	retval = kn_inject_tcp_from_params(TH_ACK, saddr, daddr, sport, dport, seq, ack, NULL, 0);
	if (retval != 0) {
		return retval;
	}
	
	/* 
	 * third packet:
	 * 
	 * RST+ACK
	 *
	 * SEQ: ACK in <<<SYN+ACK<<<  
	 * ACK: SEQ in <<<SYN+ACK<<< 
	 *
	 */
	
	seq = htonl(ntohl(tcph->th_ack) + 0);
	ack = htonl(ntohl(tcph->th_seq) + 0);
	
	retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, NULL, 0);
	if (retval != 0) {
		return retval;
	}
	
	/* 
	 * fourth packet:
	 * 
	 * RST+ACK
	 *
	 * SEQ: ACK in <<<SYN+ACK<<<  + 2
	 * ACK: SEQ in <<<SYN+ACK<<<  + 2
	 *
	 */
	
	seq = htonl(ntohl(tcph->th_ack) + 2);
	ack = htonl(ntohl(tcph->th_seq) + 2);
	
	retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, NULL, 0);
	if (retval != 0) {
		return retval;
	}
	
	return KERN_SUCCESS;
}

errno_t kn_inject_after_http (mbuf_t otgn_data)
{
	errno_t retval = 0;
	u_int32_t saddr;
	u_int32_t daddr;
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t ack;
	u_int32_t seq;
	struct ip* iph;
	struct tcphdr* tcph;
	static const char* fake_message = "220 Microsoft FTP Service\r\n";
	
	iph = (struct ip*)mbuf_data(otgn_data);
	saddr = iph->ip_src.s_addr;
	daddr = iph->ip_dst.s_addr;
	
	seq = htonl(ntohl(tcph->th_seq) + 3);
	ack = tcph->th_ack;
	
	tcph = (struct tcphdr*)((char*)iph + iph->ip_hl * 4);
	sport = tcph->th_sport;
	dport = tcph->th_dport;
	
	retval = kn_inject_tcp_from_params(TH_ACK | TH_PUSH, saddr, daddr, sport, dport, seq, ack, fake_message, strlen(fake_message));
	if (retval != 0) {
		return retval;
	}
	
	return KERN_SUCCESS;
	
}




















errno_t kn_inject_tcp_from_params(u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, const char* payload, size_t payload_len)
{
	int retval = 0;
	size_t tot_data_len, tot_buf_len, max_len; // mac osx thing.. to be safe, leave out 14 bytes for ethernet header. 
	void *buf = NULL;
	mbuf_t pkt;
	struct ip* o_iph;
	struct tcphdr* o_tcph;
	u_int16_t csum;
	mbuf_csum_request_flags_t csum_flags = 0;
    boolean_t pkt_allocated = FALSE;
	
	tot_data_len = sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;
	tot_buf_len = tot_data_len + ETHHDR_LEN;
	
	// allocate the packet
	retval = mbuf_allocpacket(MBUF_WAITOK, tot_buf_len, NULL, &pkt);
	if (retval != 0) {
		kn_debug("mbuf_allocpacket returned error %d\n", retval);
		goto FAILURE;
	}
    else {
        pkt_allocated = TRUE;
    }
	
	max_len = mbuf_maxlen(pkt);
	if (max_len < tot_buf_len) {
		kn_debug("no enough buffer space, try to request more.\n");
		retval = mbuf_prepend(&pkt, tot_buf_len - max_len, MBUF_WAITOK);
		if (retval != 0) {
			kn_debug("mbuf_prepend returned error %d\n", retval);
			goto FAILURE;
		}
	}
	
	mbuf_pkthdr_setlen(pkt, tot_data_len);
	retval = mbuf_pkthdr_setrcvif(pkt, NULL);
	if (retval != 0) {
		kn_debug("mbuf_pkthdr_setrcvif returned error %d\n", retval);
        goto FAILURE;
	}
	
	mbuf_setlen(pkt, tot_data_len);
	
	retval = mbuf_setdata(pkt, (mbuf_datastart(pkt) + ETHHDR_LEN), tot_data_len);
	if (retval != 0) {
		kn_debug("mbuf_setdata returned error %d\n", retval);
        goto FAILURE;
	}	
	
	buf = mbuf_data(pkt);
	mbuf_pkthdr_setheader(pkt, buf);
	
	o_iph = (struct ip*)buf;
	
	memset(o_iph, 0, sizeof(struct ip));
	
	// setup IPv4 header
	o_iph->ip_hl			=	sizeof(struct ip) / 4;
	o_iph->ip_v				=	4;
	o_iph->ip_tos			=	0;
	o_iph->ip_id			=	0;
	o_iph->ip_off			=	htons(IP_DF);
	o_iph->ip_p				=	IPPROTO_TCP;
	o_iph->ip_len			=	htons(tot_data_len);
	o_iph->ip_sum			=	0;
	o_iph->ip_ttl			=	64;
	o_iph->ip_src.s_addr	=	iph_saddr;
	o_iph->ip_dst.s_addr	=	iph_daddr;
	
	o_tcph = (struct tcphdr*)((char*)o_iph + sizeof(struct ip));
	
	memset(o_tcph, 0, sizeof(struct tcphdr));
    
	o_tcph->th_sport		=	tcph_sport;
	o_tcph->th_dport		=	tcph_dport;
	o_tcph->th_seq			=	tcph_seq;
	o_tcph->th_ack			=	tcph_ack;
	o_tcph->th_flags		=	tcph_flags;
	o_tcph->th_win			=	0xffffU;
	o_tcph->th_off			=	sizeof(struct tcphdr) / 4;
	o_tcph->th_sum			=	0;
	o_tcph->th_urp			=	0;
	
	if (payload_len > 0) {
		memcpy((char*)o_tcph + sizeof(struct tcphdr), payload, payload_len);
	}
	
	mbuf_clear_csum_performed(pkt);
	
	csum_flags |= MBUF_CSUM_REQ_IP;
	retval = mbuf_get_csum_requested(pkt, &csum_flags, NULL);
	if (retval != 0) {
		kn_debug("mbuf_get_csum_requested returned error %d\n", retval);
        goto FAILURE;
	}
	
	/* calculate TCP checksum */
	
	csum = kn_tcp_sum_calc(sizeof(struct tcphdr) + payload_len, (u_int16_t*)&o_iph->ip_src.s_addr, (u_int16_t*)&o_iph->ip_dst.s_addr, (u_int16_t*)o_tcph);
	o_tcph->th_sum			=	csum;
	
	retval = ipf_inject_output(pkt, kn_ipf_ref, NULL);
	if (retval != 0) {
		kn_debug("ipf_inject_output returned error %d\n", retval);
        goto FAILURE;
	}
	else {
		kn_debug("injected tcp packet, flags: 0x%X, saddr: %s, daddr: %s, ack: %d, seq: %d\n", tcph_flags, kn_inet_ntoa(iph_saddr), kn_inet_ntoa(iph_daddr), tcph_ack, tcph_seq);
	}	
    
    return KERN_SUCCESS;
	
FAILURE:
    if (pkt_allocated == TRUE) {
        mbuf_free(pkt);
    }
    
	return retval;
}


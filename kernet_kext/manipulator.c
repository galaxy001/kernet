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
#include <kern/locks.h>

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

#include "kext.h"
#include "utils.h"

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
	
	retval = kn_inject_tcp_from_params(TH_RST, saddr, daddr, sport, dport, seq, ack, NULL, 0, outgoing_direction);
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
	
	retval = kn_inject_tcp_from_params(TH_ACK, saddr, daddr, sport, dport, seq, ack, NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}
    /* This packet is critical, do it again */
//    retval = kn_inject_tcp_from_params(TH_ACK, saddr, daddr, sport, dport, seq, ack, NULL, 0, outgoing_direction);
//	if (retval != 0) {
//		return retval;
//	}
	
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
	
	retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, NULL, 0, outgoing_direction);
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
	
	retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}

    retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}

    retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}
    
	return KERN_SUCCESS;
}

errno_t kn_inject_after_http (mbuf_t otgn_data)
{
	errno_t retval = 0;
    mbuf_t otgn_data_dup;
    u_int16_t ms = 0;
    
    lck_rw_lock_exclusive(gMasterRecordLock);
    ms = master_record.http_delay_ms;
    lck_rw_unlock_exclusive(gMasterRecordLock);
    
    retval = mbuf_dup(otgn_data, MBUF_DONTWAIT, &otgn_data_dup);
    if (retval != 0) {
        kn_debug("mbuf_dup returned error %d\n", retval);
        return retval;
    }
    
    retval = kn_mbuf_set_tag(&otgn_data_dup, gidtag, kMY_TAG_TYPE, outgoing_direction);
    if (retval != 0) {
        kn_debug("kn_mbuf_set_tag returned error %d\n", retval);
        return retval;
    }
    
    retval = kn_delay_pkt_inject(otgn_data, ms, outgoing_direction);
    if (retval != 0) {
        kn_debug("kn_delay_pkt_inject returned error %d\n", retval);
        return retval;
    }
	return KERN_SUCCESS;
	
}

void kn_fulfill_ip_ranges()
{    
	// Google
	kn_append_ip_range_entry_default_ports(htonl(67305984), 24, ip_range_kernet_2);   //	4.3.2.0/24
	kn_append_ip_range_entry_default_ports(htonl(134623232), 24, ip_range_kernet_2);  //	8.6.48.0/21
	kn_append_ip_range_entry_default_ports(htonl(134743040), 24, ip_range_kernet_2);  //	8.8.4.0/24
	kn_append_ip_range_entry_default_ports(htonl(134744064), 24, ip_range_kernet_2);  //	8.8.8.0/24
	kn_append_ip_range_entry_default_ports(htonl(1078218752), 21, ip_range_kernet_2); //	64.68.80.0/21
	kn_append_ip_range_entry_default_ports(htonl(1078220800), 21, ip_range_kernet_2); //	64.68.88.0/21
	kn_append_ip_range_entry_default_ports(htonl(1089052672), 19, ip_range_kernet_2); //	64.233.160.0/19
	kn_append_ip_range_entry_default_ports(htonl(1113980928), 20, ip_range_kernet_2); //	66.102.0.0/20
	kn_append_ip_range_entry_default_ports(htonl(1123631104), 19, ip_range_kernet_2); //	66.249.64.0/19
	kn_append_ip_range_entry_default_ports(htonl(1208926208), 18, ip_range_kernet_2); //	72.14.192.0/18
	kn_append_ip_range_entry_default_ports(htonl(1249705984), 16, ip_range_kernet_2); //	74.125.0.0/16
	kn_append_ip_range_entry_default_ports(htonl(2915172352), 16, ip_range_kernet_4); //	173.194.0.0/16
    kn_append_readable_ip_range_entry_default_ports("208.117.224.0", 19, ip_range_kernet_4);
	kn_append_ip_range_entry_default_ports(htonl(3512041472), 17, ip_range_kernet_2); //	209.85.128.0/17
	kn_append_ip_range_entry_default_ports(htonl(3639549952), 19, ip_range_kernet_2); //	216.239.32.0/19
	
	// Wikipedia
    kn_append_readable_ip_range_entry_default_ports("208.80.152.0", 22, ip_range_kernet_2);
	
	// Just-Ping
	kn_append_ip_range_entry_default_ports(htonl(1161540560), 32, ip_range_kernet_2);	//	69.59.179.208/32
	
	// Dropbox
	kn_append_readable_ip_range_entry_default_ports("199.47.216.0", 22, ip_range_kernet_2);
	kn_append_readable_ip_range_entry_80_port("205.251.205.28", 24, ip_range_kernet_2);
    
    // Twitter
    kn_append_readable_ip_range_entry_80_port("199.59.148.0", 22, ip_range_kernet_4);  //199.59.148.0/22
    
    // Facebook
    kn_append_readable_ip_range_entry_80_port("69.63.176.0", 20, ip_range_kernet_3);
    kn_append_readable_ip_range_entry_80_port("69.171.224.0", 19, ip_range_kernet_3);      
    
    // Kenengba.com
    kn_append_readable_ip_range_entry_default_ports("106.187.34.220", 32, ip_range_kernet_2);
    
    // 173.212.221.150
    kn_append_readable_ip_range_entry_default_ports("173.212.221.150", 32, ip_range_kernet_3);

    // *.wordpress.com
    kn_append_readable_ip_range_entry_default_ports("74.200.243.251", 17, ip_range_kernet_3);
    kn_append_readable_ip_range_entry_default_ports("76.74.254.123", 24, ip_range_kernet_3);
    kn_append_readable_ip_range_entry_default_ports("72.233.69.6", 17, ip_range_kernet_3);
    kn_append_readable_ip_range_entry_default_ports("93.184.220.20", 24, ip_range_kernet_3);
    
}

errno_t kn_append_readable_ip_range_entry_default_ports(const char* ip, u_int8_t netmask_bits, ip_range_policy policy)
{
    errno_t retval = 0;
    u_int32_t addr = 0;
    kn_inet_aton(ip, &addr);

    retval = kn_append_ip_range_entry(addr, netmask_bits, htons(80), policy);
    if (retval != 0)
        return retval;
    retval = kn_append_ip_range_entry(addr, netmask_bits, htons(443), policy);
    if (retval != 0)
        return retval;
    return retval;
}

errno_t kn_append_readable_ip_range_entry_80_port(const char* ip, u_int8_t netmask_bits, ip_range_policy policy)
{
    errno_t retval = 0;
    u_int32_t addr = 0;
    kn_inet_aton(ip, &addr);

    retval = kn_append_ip_range_entry(addr, netmask_bits, htons(80), policy);
    return retval;
}

errno_t kn_tcp_pkt_from_params(mbuf_t *data, u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, const char* payload, size_t payload_len) 
{
    int retval = 0;
	size_t tot_data_len, tot_buf_len, max_len; // mac osx thing.. to be safe, leave out 14 bytes for ethernet header. 
	void *buf = NULL;
    struct ip* o_iph;
	struct tcphdr* o_tcph;
	u_int16_t csum;
	mbuf_csum_request_flags_t csum_flags = 0;
    boolean_t pkt_allocated = FALSE;
	
	tot_data_len = sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;
	tot_buf_len = tot_data_len + ETHHDR_LEN;
	
	// allocate the packet
	retval = mbuf_allocpacket(MBUF_DONTWAIT, tot_buf_len, NULL, data);
	if (retval != 0) {
		kn_debug("mbuf_allocpacket returned error %d\n", retval);
		goto FAILURE;
	}
    else {
        pkt_allocated = TRUE;
    }
	
	max_len = mbuf_maxlen(*data);
	if (max_len < tot_buf_len) {
		kn_debug("no enough buffer space, try to request more.\n");
		retval = mbuf_prepend(data, tot_buf_len - max_len, MBUF_DONTWAIT);
		if (retval != 0) {
			kn_debug("mbuf_prepend returned error %d\n", retval);
			goto FAILURE;
		}
	}
	
	mbuf_pkthdr_setlen(*data, tot_data_len);
	retval = mbuf_pkthdr_setrcvif(*data, NULL);
	if (retval != 0) {
		kn_debug("mbuf_pkthdr_setrcvif returned error %d\n", retval);
        goto FAILURE;
	}
	
	mbuf_setlen(*data, tot_data_len);
	
	retval = mbuf_setdata(*data, (mbuf_datastart(*data) + ETHHDR_LEN), tot_data_len);
	if (retval != 0) {
		kn_debug("mbuf_setdata returned error %d\n", retval);
        goto FAILURE;
	}	
	
	buf = mbuf_data(*data);
	mbuf_pkthdr_setheader(*data, buf);
	
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
	
	mbuf_clear_csum_performed(*data);
	
	csum_flags |= MBUF_CSUM_REQ_IP;
	retval = mbuf_get_csum_requested(*data, &csum_flags, NULL);
	if (retval != 0) {
		kn_debug("mbuf_get_csum_requested returned error %d\n", retval);
        goto FAILURE;
	}
	
	/* calculate TCP checksum */
	
	csum = kn_tcp_sum_calc(sizeof(struct tcphdr) + payload_len, (u_int16_t*)&o_iph->ip_src.s_addr, (u_int16_t*)&o_iph->ip_dst.s_addr, (u_int16_t*)o_tcph);
	o_tcph->th_sum			=	csum;
    
    return 0;
    
FAILURE:
    if (pkt_allocated == TRUE) {
        mbuf_free(*data);
    }
    
	return retval;
    
}

errno_t kn_inject_tcp_from_params(u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, const char* payload, size_t payload_len, packet_direction direction)
{
	mbuf_t pkt; 
    errno_t retval = 0;
    
    retval = kn_tcp_pkt_from_params(&pkt, tcph_flags, iph_saddr, iph_daddr, tcph_sport, tcph_dport, tcph_seq, tcph_ack, payload, payload_len);
    if (retval != 0) {
        kn_debug("kn_tcp_pkt_from_params returned error %d\n", retval);
        return retval;
    }
    
    if (direction == outgoing_direction) {
        retval = ipf_inject_output(pkt, kn_ipf_ref, NULL);
    } 
    else if (direction == incoming_direction) {
        retval = ipf_inject_input(pkt, kn_ipf_ref);
    }
    else {
        retval = EINVAL;
        kn_debug("unknown inject direction\n");
        mbuf_free(pkt);
        return retval; 
    }
	if (retval != 0) {
		kn_debug("ipf_inject_output returned error %d\n", retval);
        return retval;
    }
	else {
		kn_debug("injected tcp packet, flags: 0x%X, src: %s:%d, dst: %s:%d, ack: %u, seq: %u\n", tcph_flags, kn_inet_ntoa(iph_saddr), ntohs(tcph_sport), kn_inet_ntoa(iph_daddr), ntohs(tcph_dport), tcph_ack, tcph_seq);
	}	
    
    return 0;
	
}

#include <mach/mach_types.h>
#include <mach/vm_types.h>

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
#include "locks.h"
#include "utils.h"
#include "ip_range.h"
#include "manipulator.h"

errno_t kn_prepend_mbuf_hdr(mbuf_t *data, size_t pkt_len)
{
	mbuf_t			new_hdr;
	errno_t			status;
    
	status = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &new_hdr);
	if (KERN_SUCCESS == status)
	{
		/* we've created a replacement header, now we have to set things up */
		/* set the mbuf argument as the next mbuf in the chain */
		mbuf_setnext(new_hdr, *data);
		
		/* set the next packet attached to the mbuf argument in the pkt hdr */
		mbuf_setnextpkt(new_hdr, mbuf_nextpkt(*data));
		/* set the total chain len field in the pkt hdr */
		mbuf_pkthdr_setlen(new_hdr, pkt_len);
		mbuf_setlen(new_hdr, 0);
        
		mbuf_pkthdr_setrcvif(*data, NULL);
		
		/* now set the new mbuf_t as the new header mbuf_t */
		*data = new_hdr;
	}
	return status;
}

boolean_t kn_mbuf_check_tag(mbuf_t *m, mbuf_tag_id_t module_id, mbuf_tag_type_t tag_type, packet_direction value)
{
    errno_t	status;
	int		*tag_ref;
	size_t	len;
	
	// Check whether we have seen this packet before.
	status = mbuf_tag_find(*m, module_id, tag_type, &len, (void**)&tag_ref);
	if ((status == 0) && (*tag_ref == value) && (len == sizeof(value)))
		return TRUE;
    
	return FALSE;
}

errno_t	kn_mbuf_set_tag(mbuf_t *data, mbuf_tag_id_t id_tag, mbuf_tag_type_t tag_type, packet_direction value)
{	
	errno_t status;
	int		*tag_ref = NULL;
	size_t	len;
	
	// look for existing tag
	status = mbuf_tag_find(*data, id_tag, tag_type, &len, (void*)&tag_ref);
	// allocate tag if needed
	if (status != 0) 
	{		
		status = mbuf_tag_allocate(*data, id_tag, tag_type, sizeof(value), MBUF_WAITOK, (void**)&tag_ref);
		if (status == 0)
			*tag_ref = value;		// set tag_ref
		else if (status == EINVAL)
		{			
			mbuf_flags_t	flags;
			// check to see if the mbuf_tag_allocate failed because the mbuf_t has the M_PKTHDR flag bit not set
			flags = mbuf_flags(*data);
			if ((flags & MBUF_PKTHDR) == 0)
			{
				mbuf_t			m = *data;
				size_t			totalbytes = 0;
                
				/* the packet is missing the MBUF_PKTHDR bit. In order to use the mbuf_tag_allocate, function,
                 we need to prepend an mbuf to the mbuf which has the MBUF_PKTHDR bit set.
                 We cannot just set this bit in the flags field as there are assumptions about the internal
                 fields which there are no API's to access.
                 */
				kn_debug("mbuf_t missing MBUF_PKTHDR bit\n");
                
				while (m)
				{
					totalbytes += mbuf_len(m);
					m = mbuf_next(m);	// look at the next mbuf
				}
				status = kn_prepend_mbuf_hdr(data, totalbytes);
				if (status == KERN_SUCCESS)
				{
					status = mbuf_tag_allocate(*data, id_tag, tag_type, sizeof(value), MBUF_WAITOK, (void**)&tag_ref);
					if (status)
					{
						kn_debug("mbuf_tag_allocate failed a second time, status was %d\n", status);
					}
				}
			}
		}
		else
			kn_debug("mbuf_tag_allocate failed, status was %d\n", status);
	}
	return status;
}

kn_synack_injection_func kn_synack_injection_function_for_ip_range_policy(ip_range_policy policy)
{
    switch (policy) {
        case ip_range_direct:
            return NULL;
        case ip_range_kernet_1:
            return kn_inject_after_synack_strict;
        case ip_range_kernet_2:
            return kn_inject_after_synack_1;
        case ip_range_kernet_3:
            return kn_inject_after_synack_2;
        case ip_range_kernet_4:
            return kn_inject_after_synack_3;
        case ip_range_kernet_experiment:
            return kn_inject_after_synack_experiment;
        default:
            break;
    }
    return NULL;
}

errno_t kn_inject_after_synack_strict(mbuf_t incm_data)
{
    /* THIS DOES NOT WORK AFTER ALL !!! */
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
     * essential part 1
     * inject an FIN with bad sequence number, obfuscating the handshake.
     * it will be dropped by rfc-compliant endpoint, 
     * meanwhile thwarting eavesdroppers on the same direction (c -> s).
     */
	seq = tcph->th_ack;
	ack = tcph->th_seq;
	
	retval = kn_inject_tcp_from_params(TH_FIN, saddr, daddr, sport, dport, seq, ack, 0xffffU, NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}
    
    /*
     * essential part 2
     * inject an ACK with correct SEQ but bad ACK.
     * this causes an RST from server which should have no real impact on 
     * the original connection,
     * thus thwarts eavesdroppers on the other direction (s -> c).
     * 
     * RFC793: 
     *   2.  If the connection is in any non-synchronized state (LISTEN,
     *   SYN-SENT, SYN-RECEIVED), and the incoming segment acknowledges
     *   something not yet sent (the segment carries an unacceptable ACK),
     *   ..., a reset is sent.
     * 
     *   If the incoming segment has an ACK field, the reset takes its
     *   sequence number from the ACK field of the segment, otherwise the
     *   reset has sequence number zero and the ACK field is set to the sum
     *   of the sequence number and segment length of the incoming segment.
     *   The connection remains in the same state.
     * 
     * sometimes certain kind of rfc non-compliant tcp stacks or firewalls
     * may have unexpected response or no reply at all.
     *
     * seems that the seq is not nessesarily correct.
     */
    
    retval = kn_inject_tcp_from_params(TH_ACK, saddr, daddr, sport, dport, seq, ack, 0xffffU, NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}
    
    return 0;
}

errno_t kn_inject_after_synack_experiment (mbuf_t incm_data)
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
	
//	retval = kn_inject_tcp_from_params(TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
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
	
//	retval = kn_inject_tcp_from_params(TH_ACK, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
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
	
	seq = htonl(ntohl(tcph->th_ack) + 10000000);
	ack = htonl(ntohl(tcph->th_seq) + 0);
	
	retval = kn_inject_tcp_from_params(TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
    
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
	
//	retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}
    return KERN_SUCCESS;
}

errno_t kn_inject_after_synack_1 (mbuf_t incm_data)
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
	
	retval = kn_inject_tcp_from_params(TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
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
	
	retval = kn_inject_tcp_from_params(TH_ACK, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
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
	
	retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
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
	
	retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}
    
	retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}	
    
    retval = kn_inject_tcp_from_params(TH_ACK | TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}    
    
    return KERN_SUCCESS;
}

errno_t kn_inject_after_synack_2 (mbuf_t incm_data)
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
	
	seq = htonl(ntohl(tcph->th_ack) + 1);
	ack = tcph->th_seq;
	
	retval = kn_inject_tcp_from_params(TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0, outgoing_direction);
	if (retval != 0) {
		return retval;
	}
        
    return KERN_SUCCESS;
}

errno_t kn_inject_after_synack_3 (mbuf_t incm_data)
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
    
	seq = htonl(ntohl(tcph->th_ack));
	ack = tcph->th_seq;
	
    mbuf_t pkt; 
    
    retval = kn_tcp_pkt_from_params(&pkt, TH_RST, saddr, daddr, sport, dport, seq, ack, htons(0xffffU), NULL, 0);
    if (retval != 0) {
        kn_debug("kn_tcp_pkt_from_params returned error %d\n", retval);
        return retval;
    }
    
    kn_set_ip_ttl(&pkt, 10);
    
    retval = kn_mbuf_set_tag(&pkt, gidtag, kMY_TAG_TYPE, outgoing_direction);
    if (retval != 0) {
        kn_debug("kn_mbuf_set_tag returned error %d\n", retval);
        return retval;
    }
    
    retval = ipf_inject_output(pkt, kn_ipf_ref, NULL);
    if (retval != 0) {
		return retval;
	}
    
    return KERN_SUCCESS;
}

errno_t kn_tcp_pkt_from_params(mbuf_t *data, u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, u_int16_t tcph_win, const char* payload, size_t payload_len) 
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
	o_tcph->th_win			=	tcph_win;
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

errno_t kn_inject_tcp_from_params(u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, u_int16_t tcph_win, const char* payload, size_t payload_len, packet_direction direction)
{
	mbuf_t pkt; 
    errno_t retval = 0;
    char saddr[READABLE_IPv4_LENGTH];
    char daddr[READABLE_IPv4_LENGTH];
    
    retval = kn_tcp_pkt_from_params(&pkt, tcph_flags, iph_saddr, iph_daddr, tcph_sport, tcph_dport, tcph_seq, tcph_ack, tcph_win, payload, payload_len);
    if (retval != 0) {
        kn_debug("kn_tcp_pkt_from_params returned error %d\n", retval);
        return retval;
    }
    
    retval = kn_mbuf_set_tag(&pkt, gidtag, kMY_TAG_TYPE, outgoing_direction);
    if (retval != 0) {
        kn_debug("kn_mbuf_set_tag returned error %d\n", retval);
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
		kn_debug("injected tcp packet, flags: 0x%X, src: %s:%d, dst: %s:%d, ack: %u, seq: %u\n", tcph_flags, kn_inet_ntoa(iph_saddr, saddr), ntohs(tcph_sport), kn_inet_ntoa(iph_daddr, daddr), ntohs(tcph_dport), tcph_ack, tcph_seq);
	}	
    
    return 0;
	
}

errno_t kn_set_ip_ttl(mbuf_t *data, u_int8_t ttl) {
	struct ip* iph;
	iph = (struct ip*)mbuf_data(*data);
	iph->ip_ttl = ttl;
    return 0;
}



/* data_offset = offset of the fragmented second packet without IP header counted in */
/* not functioning ! */
static errno_t kn_fragment_pkt_to_two_pieces(mbuf_t orgn_pkt, mbuf_t *pkt1, mbuf_t *pkt2, u_int16_t data_offset)
{
    struct ip* iph;
    u_int16_t tot_len;
    u_int16_t pkt1_len;
    u_int16_t pkt2_len;
    boolean_t pkt1_allocated = FALSE;
    boolean_t pkt2_allocated = FALSE;
    errno_t retval = 0;
    char *pkt1_buf, *pkt2_buf, *orgn_buf;
    mbuf_csum_request_flags_t csum_flags = 0;
    int orgn_ip_hl = iph->ip_hl * 4;
    u_int16_t ip_id = 0x2912;
    
    if (data_offset % 8 != 0) {
        kn_debug("data_offset % 8 != 0\n");
        goto FAILURE;
    }
    
    iph = (struct ip*)mbuf_data(orgn_pkt);
    tot_len = ntohs(iph->ip_len);
    pkt1_len = orgn_ip_hl + data_offset;
    pkt2_len = tot_len - orgn_ip_hl - data_offset + sizeof(struct ip);
    
    if (data_offset < tot_len - orgn_ip_hl) {
        kn_debug("unable to fragment a packet because offset too small\n");
        goto FAILURE;
    }
    retval = mbuf_allocpacket(MBUF_DONTWAIT, pkt1_len, NULL, pkt1);
	if (retval != 0) {
		kn_debug("mbuf_allocpacket returned error %d\n", retval);
		goto FAILURE;
	}
    else {
        pkt1_allocated = TRUE;
    }
    
    retval = mbuf_allocpacket(MBUF_DONTWAIT, pkt2_len, NULL, pkt2);
	if (retval != 0) {
		kn_debug("mbuf_allocpacket returned error %d\n", retval);
		goto FAILURE;
	}
    else {
        pkt2_allocated = TRUE;
    }
	
	mbuf_pkthdr_setlen(*pkt1, pkt1_len);
	retval = mbuf_pkthdr_setrcvif(*pkt1, NULL);
	if (retval != 0) {
		kn_debug("mbuf_pkthdr_setrcvif returned error %d\n", retval);
        goto FAILURE;
	}
	
	mbuf_setlen(*pkt1, pkt1_len);
	
	retval = mbuf_setdata(*pkt1, (mbuf_datastart(*pkt1)), pkt1_len);
	if (retval != 0) {
		kn_debug("mbuf_setdata returned error %d\n", retval);
        goto FAILURE;
	}
	
    mbuf_pkthdr_setheader(*pkt1, mbuf_data(*pkt1));
    
    mbuf_pkthdr_setlen(*pkt2, pkt2_len);
	retval = mbuf_pkthdr_setrcvif(*pkt2, NULL);
	if (retval != 0) {
		kn_debug("mbuf_pkthdr_setrcvif returned error %d\n", retval);
        goto FAILURE;
	}
	
	mbuf_setlen(*pkt2, pkt2_len);
	
	retval = mbuf_setdata(*pkt2, (mbuf_datastart(*pkt2)), pkt2_len);
	if (retval != 0) {
		kn_debug("mbuf_setdata returned error %d\n", retval);
        goto FAILURE;
	}
	
    mbuf_pkthdr_setheader(*pkt2, mbuf_data(*pkt2));
    
    pkt1_buf = mbuf_data(*pkt1);
    pkt2_buf = mbuf_data(*pkt2);
    memcpy(pkt1_buf, orgn_buf, data_offset + orgn_ip_hl);
    memcpy(pkt2_buf, orgn_buf, sizeof(struct ip));
    memcpy(pkt2_buf + sizeof(struct ip), orgn_buf + orgn_ip_hl + data_offset, pkt2_len - sizeof(struct ip));
    
    iph = (struct ip*)pkt1_buf;
    iph->ip_off = 0;
    iph->ip_off = iph->ip_off | IP_MF;
    iph->ip_len = htons(pkt1_len);
    iph->ip_id  = htons(ip_id);
    
    mbuf_clear_csum_performed(*pkt1);
	
	csum_flags |= MBUF_CSUM_REQ_IP;
	retval = mbuf_get_csum_requested(*pkt1, &csum_flags, NULL);
	if (retval != 0) {
		kn_debug("mbuf_get_csum_requested returned error %d\n", retval);
        goto FAILURE;
	}
    
    iph = (struct ip*)pkt2_buf;
    iph->ip_off = data_offset / 8;
    iph->ip_len = htons(pkt2_len);
    iph->ip_id  = htons(ip_id);
    
    mbuf_clear_csum_performed(*pkt2);
    
    csum_flags = 0;
	csum_flags |= MBUF_CSUM_REQ_IP;
	retval = mbuf_get_csum_requested(*pkt2, &csum_flags, NULL);
	if (retval != 0) {
		kn_debug("mbuf_get_csum_requested returned error %d\n", retval);
        goto FAILURE;
	}
    
    return 0;
    
FAILURE:
    if (pkt1_allocated == TRUE)
        mbuf_free(*pkt1);
    if (pkt2_allocated == TRUE) 
        mbuf_free(*pkt2);
    return retval;
}


errno_t kn_repack_via_wcs2 (mbuf_t otgn_data)
{
    errno_t retval = 0;
    int orig_len = 0;	
    size_t tot_data_len, tot_buf_len, max_len;
    mbuf_t pkt;
    struct ip* i_iph;
    struct ip* o_iph;
    struct udphdr* o_udph;
    char *buf;
    boolean_t pkt_allocated = FALSE;
    u_int32_t wcs2_host = 0;
    u_int16_t wcs2_port = 0;
    u_int16_t csum;
	mbuf_csum_request_flags_t csum_flags = 0;
    
    lck_rw_lock_shared(gMasterRecordLock);
    wcs2_host = master_record.wcs2_host;
    wcs2_port = master_record.wcs2_port;
    lck_rw_unlock_shared(gMasterRecordLock);
    
    i_iph = (struct ip*)(mbuf_data(otgn_data));
    orig_len = ntohs(i_iph->ip_len);
    
    tot_data_len = sizeof(struct ip) + sizeof(struct udphdr) + orig_len;
	tot_buf_len = tot_data_len;
    
    // allocate the packet
	retval = mbuf_allocpacket(MBUF_DONTWAIT, tot_buf_len, NULL, &pkt);
	if (retval != 0) {
		kn_debug("mbuf_allocpacket returned error %d\n", retval);
		goto END;
	}
    else {
        pkt_allocated = TRUE;
    }
	
	max_len = mbuf_maxlen(pkt);
	if (max_len < tot_buf_len) {
		kn_debug("no enough buffer space, try to request more.\n");
		retval = mbuf_prepend(&pkt, tot_buf_len - max_len, MBUF_DONTWAIT);
		if (retval != 0) {
			kn_debug("mbuf_prepend returned error %d\n", retval);
			goto END;
		}
	}
	
	mbuf_pkthdr_setlen(pkt, tot_data_len);
	retval = mbuf_pkthdr_setrcvif(pkt, NULL);
	if (retval != 0) {
		kn_debug("mbuf_pkthdr_setrcvif returned error %d\n", retval);
        goto END;
	}
	
	mbuf_setlen(pkt, tot_data_len);
	
	retval = mbuf_setdata(pkt, (mbuf_datastart(pkt)), tot_data_len);
	if (retval != 0) {
		kn_debug("mbuf_setdata returned error %d\n", retval);
        goto END;
	}	
    
    buf = mbuf_data(pkt);
	mbuf_pkthdr_setheader(pkt, buf);
	
    o_iph = (struct ip*)buf;
	memset(buf, 0, tot_buf_len);
    
    o_iph->ip_hl			=	sizeof(struct ip) / 4;
	o_iph->ip_v				=	4;
	o_iph->ip_tos			=	0;
	o_iph->ip_id			=	0;
	o_iph->ip_off			=	htons(IP_DF);
	o_iph->ip_p				=	IPPROTO_UDP;
	o_iph->ip_len			=	htons(tot_data_len);
	o_iph->ip_sum			=	0;
	o_iph->ip_ttl			=	64;
	o_iph->ip_src.s_addr	=	i_iph->ip_src.s_addr;
	o_iph->ip_dst.s_addr	=	wcs2_host;
    
    o_udph = (struct udphdr*)(buf + sizeof(struct ip));
    o_udph->uh_dport = wcs2_port;
    o_udph->uh_sport = htons(54000);
    o_udph->uh_ulen =  htons(mbuf_len(otgn_data) + sizeof(struct udphdr));
    
    memcpy(buf + sizeof(struct ip) + sizeof(struct udphdr), mbuf_data(otgn_data), mbuf_len(otgn_data));
    
    csum = kn_udp_sum_calc(ntohs(o_udph->uh_ulen), (u_int16_t*)&o_iph->ip_src.s_addr, (u_int16_t*)&o_iph->ip_dst.s_addr, (u_int16_t*)(buf + sizeof(struct ip)));
	o_udph->uh_sum			=	csum;
    
    mbuf_clear_csum_performed(pkt);
	
	csum_flags |= MBUF_CSUM_REQ_IP;
	retval = mbuf_get_csum_requested(pkt, &csum_flags, NULL);
	if (retval != 0) {
		kn_debug("mbuf_get_csum_requested returned error %d\n", retval);
        goto END;
	}
    
    pkt_allocated = FALSE;
    
    retval = ipf_inject_output(pkt, kn_ipf_ref, NULL);
    if (retval == 0) {
        goto END;
    }
    else {
        kn_debug("ipf_inject_output returned error %d\n", retval);
        goto END;
    }
    
END:
    if (pkt_allocated == TRUE)
        mbuf_free(pkt);
    return retval;
}



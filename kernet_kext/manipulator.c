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
    char prefix[][16] = {"173.255.217", "173.255.211", "65.55.124", "184.168.229", "75.125.177", "210.71.219", "83.223.73", "69.60.7", "212.7.200", "98.137.133", "59.188.27", "67.205.29", "184.72.232", "69.120.160", "208.109.78", "216.146.46", "69.93.112", "66.96.130", "184.168.192", "69.163.178", "173.231.49", "85.233.202", "206.125.166", "211.20.177", "59.124.62", "173.193.138", "173.255.192", "69.163.223", "72.167.232", "202.181.238", "209.172.55", "74.200.12", "184.22.120", "209.62.55", "124.150.132", "173.247.252", "69.22.138", "192.121.86", "96.17.15", "173.193.215", "210.0.141", "76.103.88", "38.229.70", "66.84.18", "64.62.138", "67.227.181", "84.16.80", "98.137.35", "199.66.238", "4.28.128", "203.84.202", "216.18.22", "209.62.20", "184.168.70", "66.215.3", "210.59.230", "69.46.91", "174.36.105", "61.67.192", "61.67.193", "210.17.38", "202.125.172", "96.44.156", "65.49.26", "119.160.246", "208.95.172", "183.90.189", "65.55.114", "67.15.149", "209.200.169", "209.141.63", "202.126.48", "83.222.126", "208.64.126", "64.13.192", "67.212.166", "95.174.9", "202.55.234", "69.73.138", "66.151.111", "202.27.28", "202.39.235", "157.55.179", "97.74.144", "61.93.185", "140.123.188", "65.182.101", "58.64.128", "75.119.217", "69.163.142", "69.163.140", "85.214.117", "202.172.28", "92.122.217", "218.211.37", "75.119.219", "209.133.27", "109.74.247", "219.85.64", "219.85.68", "208.109.181", "111.221.71", "174.127.85", "122.147.51", "122.147.50", "195.81.251", "63.233.60", "173.236.178", "113.28.60", "118.142.2", "212.27.48", "174.140.154", "64.14.48", "72.52.124", "74.52.159", "75.119.198", "75.119.196", "74.120.121", "199.59.241", "208.69.40", "61.63.73", "72.41.14", "74.208.62", "88.86.118", "210.242.17", "199.119.201", "74.113.233", "72.167.183", "83.169.41", "208.71.44", "209.222.2", "209.222.1", "74.201.154", "62.116.181", "208.80.184", "98.139.135", "208.75.184", "212.64.146", "80.69.72", "173.231.128", "69.163.224", "202.125.90", "208.43.44", "174.129.202", "202.177.192", "173.192.24", "174.142.114", "184.173.166", "64.120.232", "208.82.16", "210.69.89", "50.23.200", "69.55.52", "174.120.129", "46.4.48", "115.146.24", "62.50.44", "208.94.241", "204.74.216", "119.63.198", "8.18.200", "70.40.216", "173.192.111", "216.52.115", "77.238.178", "67.159.55", "69.42.223", "174.121.79", "188.132.190", "27.147.14", "64.241.25", "61.63.36", "60.199.247", "69.72.177", "67.205.93", "46.163.66", "184.82.170", "88.80.16", "50.17.40", "121.50.176", "184.82.172", "72.26.228", "209.51.140", "123.242.224", "174.36.228", "184.154.48", "88.151.243", "74.208.182", "38.127.224", "195.8.215", "70.32.76", "174.143.243", "206.108.48", "216.18.194", "174.133.229", "98.142.216", "70.86.57", "208.66.65", "85.17.25", "220.228.161", "208.109.53", "50.19.20", "66.11.225", "67.228.102", "64.4.37", "219.94.192", "173.231.9", "199.187.125", "61.111.250", "23.10.69", "61.31.193", "216.139.236", "69.175.106", "208.97.136", "69.163.176", "69.163.171", "208.94.0", "68.233.230", "174.37.135", "122.147.63", "202.181.198", "184.106.180", "140.112.28", "31.170.160", "207.200.65", "107.20.142", "59.120.159", "69.147.246", "67.23.129", "216.24.199", "109.104.79", "60.199.201", "61.14.176", "208.88.182", "72.11.141", "67.228.204", "220.232.237", "207.162.210", "199.27.135", "199.27.134", "84.20.200", "72.167.51", "182.50.135", "98.136.60", "216.67.225", "72.249.109", "207.241.224", "67.205.48", "216.172.189", "67.148.71", "67.205.44", "128.241.116", "98.136.92", "69.163.192", "66.147.242", "195.234.175", "60.199.193", "106.187.35", "106.187.34", "106.187.39", "202.67.195", "140.112.172", "68.178.254", "111.92.236", "173.230.146", "75.125.121", "50.23.120", "65.49.2", "213.139.108", "213.52.252", "66.40.3", "69.163.232", "101.101.96", "46.249.33", "216.8.179", "175.45.56", "208.71.106", "208.71.107", "66.175.58", "213.186.33", "67.214.208", "124.108.105", "98.126.44", "87.106.21", "216.178.38", "184.168.81", "204.74.223", "46.4.95", "212.44.108", "130.242.18", "8.17.172", "12.130.132", "183.177.82", "64.202.189", "178.157.81", "69.58.188", "67.192.63", "174.36.241", "74.220.215", "63.251.171", "174.120.180", "60.199.252", "216.104.161", "204.9.177", "87.255.36", "76.74.159", "173.201.141", "98.129.229", "74.208.218", "70.32.81", "69.63.180", "74.82.179", "174.136.35", "218.213.85", "88.208.24", "69.175.29", "69.65.24", "202.175.3", "8.5.1", "64.78.167", "59.188.18", "184.168.120", "204.93.175", "64.88.254", "208.96.12", "220.228.175", "157.55.96", "173.245.60", "64.71.34", "64.71.33", "202.60.254", "46.51.240", "75.126.199", "207.210.108", "184.154.106", "12.69.32", "49.212.47", "74.122.174", "59.106.87", "195.242.152", "89.151.116", "96.46.7", "174.129.227", "59.105.179", "69.163.205", "174.129.228", "208.43.60", "174.121.234", "173.245.61", "216.239.38", "182.48.36", "216.239.34", "67.19.37", "72.52.81", "207.200.74", "93.170.52", "75.126.101", "208.87.35", "112.104.167", "116.251.204", "116.251.205", "210.244.31", "97.74.74", "64.74.223", "174.120.146", "67.220.90", "67.220.91", "203.131.229", "184.72.221", "67.228.81", "203.27.227", "69.170.135", "210.59.228", "174.129.32", "219.96.106", "62.75.145", "72.32.120", "203.174.49", "70.85.48", "210.242.195", "69.10.35", "174.122.246", "174.129.1", "74.208.149", "85.17.72", "173.201.216", "60.199.184", "209.143.153", "174.127.106", "67.18.91", "64.69.32", "173.230.156", "209.222.138", "199.204.248", "98.139.39", "204.145.120", "72.21.210", "184.106.20", "208.73.210", "173.252.200", "64.71.143", "65.254.248", "63.135.80", "68.178.232", "74.112.130", "209.17.74", "175.41.199", "69.197.183", "67.19.136", "95.211.149", "75.119.205", "74.220.199", "85.214.105", "205.186.139", "14.199.45", "46.4.149", "175.45.20", "96.45.180", "50.19.93", "46.20.47", "173.236.162", "203.69.37", "212.58.246", "212.58.241", "61.63.19", "46.163.85", "204.236.138", "82.98.86", "96.44.168", "124.108.94", "180.188.194", "173.201.253", "74.208.228", "69.163.242", "206.214.208", "203.85.62", 
        "38.99.106" //wenxuecity.com
    };
    int i;
    
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
    
    // Kenengba.com, included in the big list
    // kn_append_readable_ip_range_entry_default_ports("106.187.34.220", 32, ip_range_kernet_2);
    
    // 173.212.221.150
    kn_append_readable_ip_range_entry_default_ports("173.212.221.150", 32, ip_range_kernet_3);

    // *.wordpress.com
    kn_append_readable_ip_range_entry_default_ports("74.200.243.251", 17, ip_range_kernet_3);
    kn_append_readable_ip_range_entry_default_ports("76.74.254.123", 24, ip_range_kernet_3);
    kn_append_readable_ip_range_entry_default_ports("72.233.69.6", 17, ip_range_kernet_3);
    kn_append_readable_ip_range_entry_default_ports("93.184.220.20", 24, ip_range_kernet_3);
    
    for(i=sizeof(prefix)/sizeof(prefix[0])-1; i>=0; i-=1) {
        size_t len = strlen(prefix[i]);
        prefix[i][len++] = '.';
        prefix[i][len++] = '0';
        prefix[i][len++] = 0;
        kn_append_readable_ip_range_entry_80_port(prefix[i], 24, ip_range_kernet_3);
    }
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

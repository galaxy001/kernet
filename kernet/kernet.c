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


static OSMallocTag		gOSMallocTag;
static mbuf_tag_id_t	gidtag;
static boolean_t		gipFilterRegistered = FALSE;
static boolean_t		gsfltFilterRegistered = FALSE;

TAILQ_HEAD(, ip_range_entry) ip_range_queue;

//static lck_mtx_t		*gSwallowQueueMutex = NULL;

ipfilter_t kn_ipf_ref;
static struct ipf_filter kn_ipf_filter = {
	NULL,
	KERNET_BUNDLEID, 
	kn_ip_input_fn, 
	kn_ip_output_fn, 
	NULL, 
};

static struct sflt_filter kn_sflt_filter = {
	KERNET_HANDLE, 
	SFLT_GLOBAL, 
	KERNET_BUNDLEID,
	kn_sflt_unregistered_fn, 
	kn_sflt_attach_fn,
	kn_sflt_detach_fn,
	kn_sflt_notify_fn,
	NULL,
	NULL,
	kn_sflt_data_in_fn,
	kn_sflt_data_out_fn,
	kn_sflt_connect_in_fn,
	kn_sflt_connect_out_fn, 
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

/* As a matter of fact, I don't even bother to search for existing inet_ntoa in kernel space. I copied the following from freeBSD, I'm realy a bitch huh? */ 
char* kn_inet_ntoa(u_int32_t ina) 
{
	static char buf[4*sizeof "123"];
	unsigned char *ucp = (unsigned char *)&ina;
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
	return buf;
}

/* It's stupid to look over how kernel handles checksuming. I'll implement my own. 
 * Following code is grabbed from http://www.bloof.de/tcp_checksumming
 *
 */

u_int16_t kn_tcp_sum_calc(u_int16_t len_tcp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[])
{
    u_char prot_tcp=6;
    u_int32_t sum;
    int nleft;
    u_int16_t *w;
	
    sum = 0;
    nleft = len_tcp;
    w=buff;
	
    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
	
    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
    {
    	/* sum += *w&0xFF; */
		sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
    }
	
    /* add the pseudo header */
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(prot_tcp);
	
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
	
    // Take the one's complement of sum
    sum = ~sum;
	
	return ((u_int16_t) sum);
}

void kn_debug(const char *fmt, ...)
{
	va_list listp;
	char log_buffer[256];
	
	va_start(listp, fmt);
	
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, listp);
	printf("kernet: %s", log_buffer);
	
	va_end(listp);
}

errno_t kn_ip_input_fn (void *cookie, mbuf_t *data, int offset, u_int8_t protocol)
{
	u_int16_t len;
	struct ip* iph;
	struct udphdr* udph;
	struct dnshdr* dnsh;
	struct tcphdr* tcph;
	u_int32_t addr;
	int retval = 0;
	
	len = mbuf_len(*data);
	iph = (struct ip*) mbuf_data(*data);
	
	if (protocol == IPPROTO_UDP) {
		if (len < (offset + sizeof(struct udphdr)))
			return KERN_SUCCESS; // total packet length < sizeof(ip + udp)
		
		udph = (struct udphdr*)((char*)iph + offset);
		
		if (ntohs(udph->uh_sport) != 53) {
			return KERN_SUCCESS; // DNS response comes from port 53
		}
		
		len = ntohs(udph->uh_ulen);
		// enough space for dns record
		if (len < (sizeof(struct udphdr) + 12 + 16)) {
			return KERN_SUCCESS;
		}
		
		dnsh = (struct dnshdr*)((char*)udph + sizeof(struct udphdr));
		/*
		 * questions: 1; answer RRs: 1; 
		 * authority RRs: 0; Additional RRs: 0;
		 */
		if (dnsh->ques_num != htons(0x0001) || dnsh->ans_num != htons(0x0001) ||
			dnsh->auth_rrs != htons(0x0000) || dnsh->addi_rrs != htons(0x0000)) {
			return KERN_SUCCESS;
		}
		
		addr = *(u_int32_t*)((char*)udph + len - 4);
		kn_debug("resolved ip %s\t\t", kn_inet_ntoa(addr));
		
		if (addr == htonl(0x5d2e0859)
			|| addr == htonl(0xcb620741)
			|| addr == htonl(0x0807c62d)
			|| addr == htonl(0x4e10310f)
			|| addr == htonl(0x2e52ae44)
			|| addr == htonl(0xf3b9bb27)
			|| addr == htonl(0x9f6a794b)
			|| addr == htonl(0x253d369e)
			|| addr == htonl(0x3b1803ad)) {
			kn_debug("dropped. \n");
			return EJUSTRETURN;
		}
		else {
			kn_debug("okay. \n");
			return KERN_SUCCESS;
		}
	}
	else if (protocol == IPPROTO_TCP) {
		if (len < (offset + sizeof(struct udphdr)))
			return KERN_SUCCESS; // total packet length < sizeof(ip + udp)
		
		tcph = (struct tcphdr*)((char*)iph + offset);
		
		if (ntohs(tcph->th_sport) != 80) { // http? 
			return KERN_SUCCESS;
		}
		
		if (tcph->th_flags == 0x12) { // flags = ACK+SYN 
			addr = iph->ip_src.s_addr;
			kn_debug("ACK+SYN packet from %s\n", kn_inet_ntoa(addr));
			if (kn_shall_apply_kernet_to_ip(addr) == TRUE) {
				retval = kn_inject_after_synack(*data);
			}
			else {
			}
		}
	}
	
	
	return KERN_SUCCESS;
}

errno_t kn_ip_output_fn (void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
	struct ip *iph;
	struct tcphdr* tcph;
	char *payload;
	errno_t retval = 0;
	
	if (mbuf_len(*data) < sizeof(struct ip) + sizeof(struct tcphdr) + MIN_HTTP_REQUEST_LEN) {
		return KERN_SUCCESS;
	}
	
	iph = (struct ip*)mbuf_data(*data);
	if (iph->ip_p == IPPROTO_TCP) {
		
		tcph = (struct tcphdr*)((char*)iph + iph->ip_hl * 4);
		
		if (!(tcph->th_flags & TH_PUSH)) {
			kn_debug("to %s, id 0x%X, flag not TH_PUSH\n", kn_inet_ntoa(iph->ip_dst.s_addr), iph->ip_id);
			return KERN_SUCCESS;
		}
        
		if (kn_shall_apply_kernet_to_ip(iph->ip_dst.s_addr) == FALSE) {
			return KERN_SUCCESS;
		}
		
		tcph = (struct tcphdr*)((char*)iph + iph->ip_hl * 4);
		if (ntohs(iph->ip_len) < (iph->ip_hl * 4 + tcph->th_off * 4 + MIN_HTTP_REQUEST_LEN)) {
			kn_debug("to %s, data length not enough\n", kn_inet_ntoa(iph->ip_dst.s_addr));
			return KERN_SUCCESS;
		}
		
		payload = (char*)tcph + tcph->th_off;
        
		if (memcmp(payload, "GET", 3) == 0 || memcmp(payload, "POST", 4)) {
			//kn_debug("GET or POST to %s\n", kn_inet_ntoa(iph->ip_dst.s_addr));
			//retval = kn_inject_after_http(*data);
		}
	}
	
	return KERN_SUCCESS;
}

void kn_sflt_unregistered_fn (sflt_handle handle)
{
}

errno_t kn_sflt_attach_fn (void **cookie, socket_t so)
{
	return KERN_SUCCESS;
}

void kn_sflt_detach_fn (void *cookie, socket_t so)
{
	kn_debug("detached so 0x%X\n", so);
}

void kn_sflt_notify_fn (void *cookie, socket_t so, sflt_event_t event, void *param)
{
	if (event == sock_evt_connected) {
		kn_debug("notified that so 0x%X has connected.\n", so);
		//		kn_inject_kernet_from_so(so);
		//		sflt_detach(so, KERNET_HANDLE); // should raise progma error, should have been already detached! 
	}
}

errno_t kn_sflt_data_in_fn (void *cookie,socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
	return KERN_SUCCESS;
}

errno_t kn_sflt_data_out_fn (void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
	return KERN_SUCCESS;
}

errno_t kn_sflt_connect_in_fn (void *cookie, socket_t so, const struct sockaddr *from)
{
	sflt_detach(so, KERNET_HANDLE);
	return KERN_SUCCESS;
}

errno_t kn_sflt_connect_out_fn (void *cookie, socket_t so, const struct sockaddr *to)
{
	kn_debug("notified that so 0x%X attemps to connect to %s:%d\n", so, kn_inet_ntoa(((struct sockaddr_in*)to)->sin_addr.s_addr), htons(((struct sockaddr_in*)to)->sin_port));
	
	if (kn_shall_apply_kernet_to_ip(((struct sockaddr_in*)to)->sin_addr.s_addr) == FALSE) {
		sflt_detach(so, KERNET_HANDLE);
	}
	return KERN_SUCCESS;
}

boolean_t kn_shall_apply_kernet_to_ip(u_int32_t ip)
{
	struct ip_range_entry *range;
	
	TAILQ_FOREACH(range, &ip_range_queue, entries) {
		u_int32_t left = (ntohl(ip)) >> (32 - range->prefix);
		u_int32_t right = (range->ip) >> (32 - range->prefix);
		if (left == right) {
			if (range->policy == ip_range_stay_away) return FALSE;
			if (range->policy == ip_range_apply_kernet) return TRUE;
		}
	}
	
	return FALSE;
}

errno_t kn_append_ip_range_entry(u_int32_t ip, u_int8_t prefix, ip_range_policy policy)
{
	struct ip_range_entry *range = (struct ip_range_entry*)OSMalloc(sizeof(struct ip_range_entry), gOSMallocTag);
	if (range == NULL) return -1;
	
	range->ip = ip;
	range->prefix = prefix;
	range->policy = policy;
	
	TAILQ_INSERT_TAIL(&ip_range_queue, range, entries);
	
    return 0;
}

void kn_fulfill_ip_ranges()
{
	// Google
	kn_append_ip_range_entry((67305984), 24, ip_range_apply_kernet);   //	4.3.2.0/24
	kn_append_ip_range_entry((134623232), 24, ip_range_apply_kernet);  //	8.6.48.0/21
	kn_append_ip_range_entry((134743040), 24, ip_range_apply_kernet);  //	8.8.4.0/24
	kn_append_ip_range_entry((134744064), 24, ip_range_apply_kernet);  //	8.8.8.0/24
	kn_append_ip_range_entry((1078218752), 21, ip_range_apply_kernet); //	64.68.80.0/21
	kn_append_ip_range_entry((1078220800), 21, ip_range_apply_kernet); //	64.68.88.0/21
	kn_append_ip_range_entry((1089052672), 19, ip_range_apply_kernet); //	64.233.160.0/19
	kn_append_ip_range_entry((1113980928), 20, ip_range_apply_kernet); //	66.102.0.0/20
	kn_append_ip_range_entry((1123631104), 19, ip_range_apply_kernet); //	66.249.64.0/19
	kn_append_ip_range_entry((1208926208), 18, ip_range_apply_kernet); //	72.14.192.0/18
	kn_append_ip_range_entry((1249705984), 16, ip_range_apply_kernet); //	74.125.0.0/16
	kn_append_ip_range_entry((2915172352), 16, ip_range_apply_kernet); //	173.194.0.0/16
	kn_append_ip_range_entry((3512041472), 17, ip_range_apply_kernet); //	209.85.128.0/17
	kn_append_ip_range_entry((3639549952), 19, ip_range_apply_kernet); //	216.239.32.0/19
	
	// Wikipedia
	kn_append_ip_range_entry((3494942720), 22, ip_range_apply_kernet); //	208.80.152.0/22
	
	// Pornhub
	kn_append_ip_range_entry((2454899747), 32, ip_range_apply_kernet); //	146.82.204.35/32
	
	// Just-Ping
	kn_append_ip_range_entry((1161540560), 32, ip_range_apply_kernet);	//	69.59.179.208/32
	
	// Dropbox
	kn_append_ip_range_entry((3492530741), 32, ip_range_apply_kernet);	//	208.43.202.53/32
	kn_append_ip_range_entry((2921607977), 32, ip_range_apply_kernet);	//	174.36.51.41/32
	
	// Twitter
	kn_append_ip_range_entry((2163406116), 32, ip_range_apply_kernet); //	128.242.245.36/32
    
    kn_append_ip_range_entry((2916408726), 32, ip_range_apply_kernet); //	173.212.221.150
    
}

kern_return_t com_ccp0101_kext_kernet_start (kmod_info_t * ki, void * d) {
	
	int retval = 0;
	
	gOSMallocTag = OSMalloc_Tagalloc(KERNET_BUNDLEID, OSMT_DEFAULT); // don't want the flag set to OSMT_PAGEABLE since
	// it would indicate that the memory was pageable.
	if (gOSMallocTag == NULL)
		goto WTF;	
	
	TAILQ_INIT(&ip_range_queue);
	kn_fulfill_ip_ranges();
	
	retval = mbuf_tag_id_find(KERNET_BUNDLEID , &gidtag);
	if (retval != 0)
	{
		kn_debug("mbuf_tag_id_find returned error %d\n", retval);
		goto WTF;
	}
	
	retval = ipf_addv4(&kn_ipf_filter, &kn_ipf_ref);
	if (retval != 0)
	{
		kn_debug("ipf_addv4 returned error %d\n", retval);
		goto WTF;
	}
	else {
		gipFilterRegistered = TRUE;
	}
	
	retval = sflt_register(&kn_sflt_filter, PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (retval != 0)
	{
		kn_debug("sflt_returned error %d\n", retval);
		goto WTF;
	}
	else {
		gsfltFilterRegistered = TRUE;
	}
	
	kn_debug("extension has been loaded.\n");
    return KERN_SUCCESS;
	
WTF:
	if (gsfltFilterRegistered == TRUE) {
		sflt_unregister(KERNET_HANDLE);
		gsfltFilterRegistered = FALSE;
	}
	
	if (gipFilterRegistered == TRUE) {
		ipf_remove(kn_ipf_ref);
		gipFilterRegistered = FALSE;
	}
	
	kn_debug("extension failed to start.\n");
	return KERN_FAILURE;
}


kern_return_t com_ccp0101_kext_kernet_stop (kmod_info_t * ki, void * d) {
	
	int retval = 0;
	struct ip_range_entry *range;
	
	while ((range = TAILQ_FIRST(&ip_range_queue))) {
		TAILQ_REMOVE(&ip_range_queue, range, entries);
		OSFree(range, sizeof(struct ip_range_entry), gOSMallocTag);
	}
	
	if (gsfltFilterRegistered == TRUE) {
		retval = sflt_unregister(KERNET_HANDLE);
		if (retval != 0) {
			kn_debug("sflt_unreturned error %d\n", retval);
			goto WTF;
		}
	}
	
	if (gipFilterRegistered == TRUE) {
		retval = ipf_remove(kn_ipf_ref);
		if (retval != 0) {
			kn_debug("ipf_remove returned error %d\n", retval);
			goto WTF;
		}
	}
	
	kn_debug("extension has been unloaded.\n");
    return KERN_SUCCESS;
	
WTF:
	kn_debug("extension failed to stop.\n");
	return KERN_FAILURE;
}


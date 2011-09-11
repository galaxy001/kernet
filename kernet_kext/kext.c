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

OSMallocTag		gOSMallocTag;
mbuf_tag_id_t	gidtag;
boolean_t		gipFilterRegistered = FALSE;
boolean_t		gsfltFilterRegistered = FALSE;
boolean_t       gKernCtlRegistered = FALSE;

struct master_record_t master_record;

TAILQ_HEAD(delayed_inject_queue, delayed_inject_entry);
TAILQ_HEAD(ip_range_queue, ip_range_entry);

struct ip_range_queue ip_range_queue;
struct delayed_inject_queue delayed_inject_queue;

lck_rw_t		*gMasterRecordLock = NULL;
lck_mtx_t		*gDelayedInjectQueueMutex = NULL;
lck_rw_t        *gipRangeQueueLock  = NULL;
lck_grp_t		*gMutexGroup = NULL;

ipfilter_t kn_ipf_ref;
kern_ctl_ref kn_ctl_ref;

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

static struct kern_ctl_reg kn_ctl_reg = {
	KERNET_BUNDLEID,
	0,
	0,
	0, 
	0,
	(1024),
	kn_ctl_connect_fn,
	kn_ctl_disconnect_fn,
	kn_ctl_send_fn,
	kn_ctl_setopt_fn,
	kn_ctl_getopt_fn,
};

/* As a matter of fact, I don't even bother to search for existing inet_ntoa in kernel space. I copied the following from freeBSD, I'm realy a bitch huh? */ 
char* kn_inet_ntoa_simple(u_int32_t ina) 
{
	static char buf[READABLE_IPv4_LENGTH];
	unsigned char *ucp = (unsigned char *)&ina;
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
	return buf;
}

char* kn_inet_ntoa(u_int32_t ina, char* buf) {
	unsigned char *ucp = (unsigned char *)&ina;
	snprintf(buf, READABLE_IPv4_LENGTH, "%d.%d.%d.%d", ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
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

u_int16_t kn_udp_sum_calc(u_int16_t len_udp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[])
{
    u_int32_t sum;
    int nleft;
    u_int16_t *w;
	
    sum = 0;
    nleft = len_udp;
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
    sum += htons(len_udp);
    sum += htons(IPPROTO_UDP);
	
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

void kn_mr_initialize()
{
    bzero(&master_record, sizeof(master_record));
    master_record.http_delay_ms = 100;
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
		kn_debug("resolved ip %s\t\t", kn_inet_ntoa_simple(addr));
		
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
		
		if (tcph->th_flags & TH_SYN) { // flags & SYN 
			addr = iph->ip_src.s_addr;
			if (kn_shall_apply_kernet_to_host(addr, tcph->th_sport) == TRUE) {
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
    u_int32_t min_len;
	errno_t retval = 0;
	
	iph = (struct ip*)mbuf_data(*data);
	
    if (kn_mbuf_check_tag(data, gidtag, kMY_TAG_TYPE, outgoing_direction) == TRUE) {
        return KERN_SUCCESS;
    }
    
	if (ntohs(iph->ip_len) < (sizeof(struct ip) + sizeof(struct tcphdr) + MIN_HTTP_REQUEST_LEN)) {
		return KERN_SUCCESS;
	}
    
#ifdef WCS2
    if (kn_shall_apply_wcs2_to_ip(iph->ip_dst.s_addr) == TRUE) {
        boolean_t dropPacket = FALSE;
        if (iph->ip_p == IPPROTO_TCP) {
            tcph = (struct tcphdr*)((char*)iph + iph->ip_hl * 4);
            
            if (!(tcph->th_flags & TH_SYN)) {
                dropPacket = TRUE;
            }
        }
        
        if (kn_repack_via_wcs2(*data) == 0 && dropPacket == TRUE) {
            return EJUSTRETURN;
        }
        else 
            return KERN_SUCCESS;
    }
#endif
    
	if (iph->ip_p == IPPROTO_TCP) {
        
		tcph = (struct tcphdr*)((char*)iph + iph->ip_hl * 4);
		
		if (!(tcph->th_flags & TH_PUSH)) {
			return KERN_SUCCESS;
		}
        
		if (kn_shall_apply_kernet_to_host(iph->ip_dst.s_addr, tcph->th_dport) == FALSE) {
			return KERN_SUCCESS;
		}
		
		tcph = (struct tcphdr*)((char*)iph + iph->ip_hl * 4);
        min_len = (iph->ip_hl * 4  + tcph->th_off * 4 + MIN_HTTP_REQUEST_LEN);
		if (ntohs(iph->ip_len) < min_len) {
			return KERN_SUCCESS;
		}
		
		payload = (char*)tcph + tcph->th_off;
        
		if (memcmp(payload, "GET", 3) == 0 || memcmp(payload, "POST", 4)) {
			kn_debug("ip_id 0x%x, GET or POST to %s\n", htons(iph->ip_id), kn_inet_ntoa_simple(iph->ip_dst.s_addr));
			retval = kn_delayed_reinject(*data);
            return EJUSTRETURN;
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
}

void kn_sflt_notify_fn (void *cookie, socket_t so, sflt_event_t event, void *param)
{
	if (event == sock_evt_connected) {
		kn_debug("notified that so 0x%X has connected.\n", so);
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
    sflt_detach(so, KERNET_HANDLE);
	return KERN_SUCCESS;
}

boolean_t kn_shall_apply_kernet_to_host(u_int32_t ip, u_int16_t port)
{
	struct ip_range_entry *range;
    boolean_t ret = FALSE;
	
    lck_rw_lock_shared(gipRangeQueueLock);
	TAILQ_FOREACH(range, &ip_range_queue, link) {
		u_int32_t left = (ntohl(ip)) >> (32 - range->prefix);
		u_int32_t right = (ntohl(range->ip)) >> (32 - range->prefix);
		if (left == right && (range->port == 0 ? TRUE : range->port == port)) {
			if (range->policy == ip_range_stay_away) {
                ret = FALSE;
                break;
            }
			if (range->policy == ip_range_apply_kernet) {
                ret = TRUE;
                break;
            };
		}
	}
    lck_rw_unlock_shared(gipRangeQueueLock);
    
	return ret;
}

#ifdef WCS2
boolean_t kn_shall_apply_wcs2_to_ip(uint32_t ip)
{
    struct ip_range_entry *range;
	
    lck_rw_lock_shared(gipRangeQueueLock);
	TAILQ_FOREACH(range, &ip_range_queue, link) {
		u_int32_t left = (ntohl(ip)) >> (32 - range->prefix);
		u_int32_t right = (ntohl(range->ip)) >> (32 - range->prefix);
		if (left == right) {
			if (range->policy == ip_range_apply_wcs2) return TRUE;
		}
	}
    lck_rw_unlock_shared(gipRangeQueueLock);
    
	return FALSE;
}
#endif

errno_t kn_append_ip_range_entry(u_int32_t ip, u_int8_t prefix, u_int16_t port, ip_range_policy policy)
{
    struct ip_range_entry *range = NULL;
    errno_t retval = 0;
    lck_rw_lock_exclusive(gipRangeQueueLock);

    TAILQ_FOREACH(range, &ip_range_queue, link) {
        if (range->ip == ip && range->prefix == prefix && (range->port == 0 ? TRUE : range->port == port)) {
            if (range->policy == policy) {
                retval = E_ALREADY_EXIST;
            }
            else {
                range->policy = policy;
                retval = E_UPDATED;
            }
            goto END;
        }
    }
    
	range = (struct ip_range_entry*)OSMalloc(sizeof(struct ip_range_entry), gOSMallocTag);
	if (range == NULL) {
        retval = ENOMEM;
        goto END;
    }
	
	range->ip = ip;
	range->prefix = prefix;
	range->policy = policy;
    range->port = port;
    
    kn_debug("appended ip range %s/%d for port %d\n", kn_inet_ntoa_simple(range->ip), range->prefix, ntohs(range->port));
    
	TAILQ_INSERT_TAIL(&ip_range_queue, range, link);
    
    goto END;
    
END:
    lck_rw_unlock_exclusive(gipRangeQueueLock);
    
    return retval;
}

errno_t kn_remove_ip_range_entry(u_int32_t ip, u_int8_t prefix, u_int16_t port)
{
	struct ip_range_entry *range, *range_to_remove = NULL;
    
    lck_rw_lock_exclusive(gipRangeQueueLock);
    TAILQ_FOREACH(range, &ip_range_queue, link) {
        if (range->ip == ip && range->prefix == prefix && range->port == port) {
            range_to_remove = range;
            break;
        }
    }
    if (range_to_remove) { 
        TAILQ_REMOVE(&ip_range_queue, range_to_remove, link);
    }
    lck_rw_unlock_exclusive(gipRangeQueueLock);
    
    if (range_to_remove) 
        return 0;
    else 
        return E_DONT_EXIT;
}

errno_t kn_append_ip_range_entry_default_ports(u_int32_t ip, u_int8_t prefix, ip_range_policy policy)
{
    errno_t retval = 0;
    retval = kn_append_ip_range_entry(ip, prefix, htons(80), policy);
    if (retval != 0)
        return retval;
    retval = kn_append_ip_range_entry(ip, prefix, htons(443), policy);
    if (retval != 0)
        return retval;
    return retval;
}

errno_t kn_remove_ip_range_entry_default_ports(u_int32_t ip, u_int8_t prefix)
{
    errno_t retval = 0;
    retval = kn_remove_ip_range_entry(ip, prefix, htons(80));
    if (retval != 0)
        return retval;
    retval = kn_remove_ip_range_entry(ip, prefix, htons(443));
    if (retval != 0)
        return retval;
    return retval;
}
            
errno_t kn_delay_pkt_inject(mbuf_t pkt, u_int32_t ms, packet_direction direction)
{
    struct delayed_inject_entry* entry;
    errno_t retval = 0;
    struct timespec ts;
    
    entry = (struct delayed_inject_entry*)OSMalloc(sizeof(struct delayed_inject_entry), gOSMallocTag);
    if (entry == NULL) {
        return ENOMEM;
    }
    
    entry->pkt = pkt;
    entry->timeout = ms;
    entry->direction = direction;
    microtime(&entry->timestamp);
    
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000 * ms;
    lck_mtx_lock(gDelayedInjectQueueMutex);
    TAILQ_INSERT_TAIL(&delayed_inject_queue, entry, link);
    lck_mtx_unlock(gDelayedInjectQueueMutex);
    
    bsd_timeout(kn_delayed_inject_timeout, (void*)entry, &ts);
    
    kn_debug("kn_delay_pkt_inject put packet in queue.\n");
    
    return retval;
    
FAILTURE:
    OSFree(entry, sizeof(struct delayed_inject_entry), gOSMallocTag);
    
    return retval;
}

boolean_t kn_delayed_inject_entry_in_queue(struct delayed_inject_entry* entry)
{
    struct delayed_inject_entry* enum_entry;
    boolean_t ret = FALSE;
    
    TAILQ_FOREACH(enum_entry, &delayed_inject_queue, link) {
        if (enum_entry == entry) {
            ret = TRUE;
            goto END;
        }
    }
    
END:
    return ret;
}
void kn_delayed_inject_timeout(void* param) 
{
    struct delayed_inject_entry* entry = param;
    mbuf_t pkt;
    struct timeval tv_now, tv_diff;
    long ms_diff;
    errno_t retval = 0;
        
    lck_mtx_lock(gDelayedInjectQueueMutex);
    
    if (kn_delayed_inject_entry_in_queue(entry) == FALSE) {
        goto END;
    }
    
    pkt = entry->pkt;
    microtime(&tv_now);
    
    timersub(&tv_now, &entry->timestamp, &tv_diff);
    ms_diff = tv_diff.tv_sec * 1000 + tv_diff.tv_usec / 1000;
    
    if (entry->direction == outgoing_direction) {
        retval = ipf_inject_output(pkt, kn_ipf_ref, NULL);
    } 
    else if (entry->direction == incoming_direction) {
        retval = ipf_inject_input(pkt, kn_ipf_ref);
    }
    else {
        mbuf_free(pkt);
        kn_debug("unknown delayed inject direction\n");
        goto FREE_AND_END;
    }
	if (retval != 0) {
		kn_debug("%dms delayed ipf_inject_output returned error %d\n", ms_diff, retval);
        goto FREE_AND_END;
    }
	else {
		kn_debug("injected tcp packet after %dms\n", ms_diff);
        goto FREE_AND_END;
	}
FREE_AND_END:
    TAILQ_REMOVE(&delayed_inject_queue, entry, link);
    OSFree(entry, sizeof(struct delayed_inject_entry), gOSMallocTag);
    goto END;
    
END:
    lck_mtx_unlock(gDelayedInjectQueueMutex);
    return;
}

errno_t kn_alloc_locks()
{
	errno_t			result = 0;
	
	gMutexGroup = lck_grp_alloc_init(KERNET_BUNDLEID, LCK_GRP_ATTR_NULL);
	if (gMutexGroup == NULL)
	{
		kn_debug("lck_grp_alloc_init returned error\n");
		result = ENOMEM;
	}
	
	if (result == 0)
	{
		gipRangeQueueLock = lck_rw_alloc_init(gMutexGroup, LCK_ATTR_NULL);
		if (gipRangeQueueLock == NULL)
		{
			kn_debug("lck_mtx_alloc_init returned error\n");
			result = ENOMEM;
		}
		if (result == 0)
		{
            gDelayedInjectQueueMutex = lck_mtx_alloc_init(gMutexGroup, LCK_ATTR_NULL);
            if (gDelayedInjectQueueMutex == NULL)
            {
                kn_debug("lck_mtx_alloc_init returned error\n");
                result = ENOMEM;
            }
            if (result == 0)
            {
                gMasterRecordLock = lck_rw_alloc_init(gMutexGroup, LCK_ATTR_NULL);
                if (gMasterRecordLock == NULL)
                {
                    kn_debug("lck_mtx_alloc_init returned error\n");
                    result = ENOMEM;
                }
            }
		}
	}
	
	return result;	// if we make it here, return success
}
errno_t kn_free_locks()
{	
 	if (gipRangeQueueLock)
	{
		lck_rw_free(gipRangeQueueLock, gMutexGroup);
		gipRangeQueueLock = NULL;
	}
	if (gDelayedInjectQueueMutex)
	{
		lck_mtx_free(gDelayedInjectQueueMutex, gMutexGroup);
		gDelayedInjectQueueMutex = NULL;
	}
    if (gMasterRecordLock) 
    {
        lck_rw_free(gMasterRecordLock, gMutexGroup);
        gMasterRecordLock = NULL;
    }
    if (gMutexGroup) {
        lck_grp_free(gMutexGroup);
        gMutexGroup = NULL;
    }
    return 0;
}
errno_t kn_alloc_queues() 
{
    TAILQ_INIT(&ip_range_queue);
    TAILQ_INIT(&delayed_inject_queue);
	kn_fulfill_ip_ranges();
    return 0;
}
errno_t kn_free_queues()
{
    void *entry = NULL;
    
    while ((entry = TAILQ_FIRST(&ip_range_queue))) {
		TAILQ_REMOVE(&ip_range_queue, (struct ip_range_entry*)entry, link);
		OSFree(entry, sizeof(struct ip_range_entry), gOSMallocTag);
	}
    return 0;
}

kern_return_t com_ccp0101_kext_kernet_start (kmod_info_t * ki, void * d) {
	
	int retval = 0;
	
	gOSMallocTag = OSMalloc_Tagalloc(KERNET_BUNDLEID, OSMT_DEFAULT); // don't want the flag set to OSMT_PAGEABLE since
	// it would indicate that the memory was pageable.
	if (gOSMallocTag == NULL)
        goto WTF;	
    
    kn_mr_initialize();
    
    retval = kn_alloc_locks();
    if (retval != 0)
	{
		kn_debug("kn_alloc_locks returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_alloc_queues();
    if (retval != 0) {
        kn_debug("kn_alloc_queues returned error %d\n", retval);
        goto WTF;
    }
    
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
	
    retval = ctl_register(&kn_ctl_reg, &kn_ctl_ref);
	if (retval == 0) {
		kn_debug("ctl_register id 0x%x, ref 0x%x \n", kn_ctl_reg.ctl_id, kn_ctl_ref);
		gKernCtlRegistered = TRUE;
	}
	else
	{
		kn_debug("ctl_register returned error %d\n", retval);
		goto WTF;
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
    
    if (gKernCtlRegistered == TRUE) {
        retval = ctl_deregister(kn_ctl_ref);
        gKernCtlRegistered = FALSE;
    }
    
    kn_free_locks();
    
    if (gOSMallocTag)
    {
        OSMalloc_Tagfree(gOSMallocTag);
        gOSMallocTag = NULL;
    }
	
	kn_debug("extension failed to start.\n");
	return KERN_FAILURE;
}


kern_return_t com_ccp0101_kext_kernet_stop (kmod_info_t * ki, void * d) {
	
	int retval = 0;
    
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
    
    if (gKernCtlRegistered == TRUE) {
        retval = ctl_deregister(kn_ctl_ref);
        gKernCtlRegistered = FALSE;
    }
    
    kn_free_queues();
    kn_free_locks();
    
    if (gOSMallocTag)
    {
        OSMalloc_Tagfree(gOSMallocTag);
        gOSMallocTag = NULL;
    }
    
	kn_debug("extension has been unloaded.\n");
    return KERN_SUCCESS;
	
WTF:
	kn_debug("extension failed to stop.\n");
	return KERN_FAILURE;
}

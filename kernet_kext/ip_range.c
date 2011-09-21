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
#include "locks.h"
#include "control.h"
#include "ip_range.h"
#include "utils.h"

TAILQ_HEAD(ip_range_list, ip_range_entry);
struct ip_range_list ip_range_list;

void kn_fulfill_ip_ranges()
{    
	// Google
	kn_append_ip_range_entry_default_ports(htonl(67305984), 24, ip_range_apply_kernet);   //	4.3.2.0/24
	kn_append_ip_range_entry_default_ports(htonl(134623232), 24, ip_range_apply_kernet);  //	8.6.48.0/21
	kn_append_ip_range_entry_default_ports(htonl(134743040), 24, ip_range_apply_kernet);  //	8.8.4.0/24
	kn_append_ip_range_entry_default_ports(htonl(134744064), 24, ip_range_apply_kernet);  //	8.8.8.0/24
	kn_append_ip_range_entry_default_ports(htonl(1078218752), 21, ip_range_apply_kernet); //	64.68.80.0/21
	kn_append_ip_range_entry_default_ports(htonl(1078220800), 21, ip_range_apply_kernet); //	64.68.88.0/21
	kn_append_ip_range_entry_default_ports(htonl(1089052672), 19, ip_range_apply_kernet); //	64.233.160.0/19
	kn_append_ip_range_entry_default_ports(htonl(1113980928), 20, ip_range_apply_kernet); //	66.102.0.0/20
	kn_append_ip_range_entry_default_ports(htonl(1123631104), 19, ip_range_apply_kernet); //	66.249.64.0/19
	kn_append_ip_range_entry_default_ports(htonl(1208926208), 18, ip_range_apply_kernet); //	72.14.192.0/18
	kn_append_ip_range_entry_default_ports(htonl(1249705984), 16, ip_range_apply_kernet); //	74.125.0.0/16
	kn_append_ip_range_entry_default_ports(htonl(2915172352), 16, ip_range_apply_kernet); //	173.194.0.0/16
	kn_append_ip_range_entry_default_ports(htonl(3512041472), 17, ip_range_apply_kernet); //	209.85.128.0/17
	kn_append_ip_range_entry_default_ports(htonl(3639549952), 19, ip_range_apply_kernet); //	216.239.32.0/19
	
	// Wikipedia
    kn_append_readable_ip_range_entry_default_ports("208.80.152.0", 22, ip_range_apply_kernet);
	
	// Just-Ping
	kn_append_ip_range_entry_default_ports(htonl(1161540560), 32, ip_range_apply_kernet);	//	69.59.179.208/32
	
	// Dropbox
	kn_append_readable_ip_range_entry_default_ports("199.47.216.0", 22, ip_range_apply_kernet);
    
    // Twitter
	kn_append_ip_range_entry_default_ports(htonl(2163406116), 32, ip_range_apply_kernet); //	128.242.245.36/32
    kn_append_readable_ip_range_entry_default_ports("199.59.148.0", 22, ip_range_apply_kernet);  //199.59.148.0/22
    
    // Facebook
    kn_append_readable_ip_range_entry_default_ports("69.63.176.0", 20, ip_range_apply_kernet);  //199.59.148.0/22
    
    // Kenengba.com
    kn_append_readable_ip_range_entry_default_ports("106.187.34.220", 32, ip_range_apply_kernet);

    // liruqi.me
    kn_append_readable_ip_range_entry_default_ports("74.207.250.143", 32, ip_range_apply_kernet);
    
    // apps.facebook.com
    kn_append_readable_ip_range_entry_default_ports("69.63.181.68", 32, ip_range_apply_kernet);
    
    // blog.wenxuecity.com
    kn_append_readable_ip_range_entry_default_ports("38.99.106.33", 24, ip_range_apply_kernet);
}

errno_t kn_ip_range_initialize()
{
    TAILQ_INIT(&ip_range_list);
	kn_fulfill_ip_ranges();
    return 0;
}

errno_t kn_ip_range_close()
{
    void *entry = NULL;
    while ((entry = TAILQ_FIRST(&ip_range_list))) {
		TAILQ_REMOVE(&ip_range_list, (struct ip_range_entry*)entry, link);
		OSFree(entry, sizeof(struct ip_range_entry), gOSMallocTag);
	}
    return 0;
}

boolean_t kn_shall_apply_kernet_to_host(u_int32_t ip, u_int16_t port)
{
	struct ip_range_entry *range;
    boolean_t ret = FALSE;
	
    lck_rw_lock_shared(gipRangeListLock);
	TAILQ_FOREACH(range, &ip_range_list, link) {
		u_int32_t left = (ntohl(ip)) >> (32 - range->netmask_bits);
		u_int32_t right = (ntohl(range->ip)) >> (32 - range->netmask_bits);
		if (left == right && (range->port == 0 ? TRUE : range->port == port)) {
			if (range->policy == ip_range_direct) {
                ret = FALSE;
                break;
            }
			if (range->policy == ip_range_apply_kernet) {
                ret = TRUE;
                break;
            };
		}
	}
    lck_rw_unlock_shared(gipRangeListLock);
    
	return ret;
}

errno_t kn_append_ip_range_entry(u_int32_t ip, u_int8_t netmask_bits, u_int16_t port, ip_range_policy policy)
{
    struct ip_range_entry *range = NULL;
    errno_t retval = 0;
    lck_rw_lock_exclusive(gipRangeListLock);
    
    TAILQ_FOREACH(range, &ip_range_list, link) {
        if (range->ip == ip && range->netmask_bits == netmask_bits && (range->port == 0 ? TRUE : range->port == port)) {
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
	range->netmask_bits = netmask_bits;
	range->policy = policy;
    range->port = port;
    
    kn_debug("appended ip range %s/%d for port %d\n", kn_inet_ntoa_simple(range->ip), range->netmask_bits, ntohs(range->port));
    
	TAILQ_INSERT_TAIL(&ip_range_list, range, link);
    
    goto END;
    
END:
    lck_rw_unlock_exclusive(gipRangeListLock);
    
    return retval;
}

errno_t kn_remove_ip_range_entry(u_int32_t ip, u_int8_t netmask_bits, u_int16_t port)
{
	struct ip_range_entry *range, *range_to_remove = NULL;
    
    lck_rw_lock_exclusive(gipRangeListLock);
    TAILQ_FOREACH(range, &ip_range_list, link) {
        if (range->ip == ip && range->netmask_bits == netmask_bits && range->port == port) {
            range_to_remove = range;
            break;
        }
    }
    if (range_to_remove) { 
        TAILQ_REMOVE(&ip_range_list, range_to_remove, link);
    }
    lck_rw_unlock_exclusive(gipRangeListLock);
    
    if (range_to_remove) 
        return 0;
    else 
        return E_DONT_EXIT;
    
}

errno_t kn_append_ip_range_entry_default_ports(u_int32_t ip, u_int8_t netmask_bits, ip_range_policy policy)
{
    errno_t retval = 0;
    retval = kn_append_ip_range_entry(ip, netmask_bits, htons(80), policy);
    if (retval != 0)
        return retval;
    retval = kn_append_ip_range_entry(ip, netmask_bits, htons(443), policy);
    if (retval != 0)
        return retval;
    return retval;
}

errno_t kn_remove_ip_range_entry_default_ports(u_int32_t ip, u_int8_t netmask_bits)
{
    errno_t retval = 0;
    retval = kn_remove_ip_range_entry(ip, netmask_bits, htons(80));
    if (retval != 0)
        return retval;
    retval = kn_remove_ip_range_entry(ip, netmask_bits, htons(443));
    if (retval != 0)
        return retval;
    return retval;
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
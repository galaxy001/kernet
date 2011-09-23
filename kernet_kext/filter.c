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
#include "connection.h"
#include "locks.h"
#include "ip_range.h"
#include "utils.h"
#include "manipulator.h"
#include "control.h"
#include "filter.h"
#include "mr.h"

boolean_t		gipFilterRegistered = FALSE;
boolean_t		gsfltFilterRegistered = FALSE;

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
	
	if (kn_mr_fake_DNS_response_dropping_enabled_safe() && protocol == IPPROTO_UDP) {
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
		if (len < (offset + sizeof(struct tcphdr)))
			return KERN_SUCCESS; // total packet length < sizeof(ip + tcp)
		
		tcph = (struct tcphdr*)((char*)iph + offset);
        
        if (kn_mr_RST_detection_enabled_safe() && (tcph->th_flags & TH_RST)) {
            struct connection_block *cb = kn_find_connection_block_with_address_in_list(iph->ip_dst.s_addr, iph->ip_src.s_addr, tcph->th_dport, tcph->th_sport);
            if (cb) {
                if (kn_cb_state(cb)) {
                    kn_debug("cb: 0x%X received RST\n", cb);
                    kn_cb_set_state(cb, received_RST);
                    kn_cb_reinject_deferred_packets(cb);
                    sflt_detach(cb->socket, KERNET_HANDLE);
                }
                else {
                    kn_debug("cb: 0x%X received RST but state is not injected_RST\n", cb);
                }
            }
            else {
                kn_debug("RST received, no control block found\n");
            }
        }
		
		if (kn_mr_injection_enabled_safe() && (tcph->th_flags & TH_SYN)) { // flags & SYN 
            struct connection_block *cb = kn_find_connection_block_with_address_in_list(iph->ip_dst.s_addr, iph->ip_src.s_addr, tcph->th_dport, tcph->th_sport);
            if (cb) {
                retval = kn_inject_after_synack(*data);
                if (retval == 0) {
                    kn_cb_set_state(cb, injected_RST);
                    kn_debug("cb: 0x%X injected RST\n", cb);
                }
            }
            else {
                kn_debug("SYN received, no control block found\n");
            }
		}
	}
	
	return KERN_SUCCESS;
}

errno_t kn_ip_output_fn (void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
	struct ip *iph;
	struct tcphdr* tcph;
	
	iph = (struct ip*)mbuf_data(*data);
	
    if (kn_mbuf_check_tag(data, gidtag, kMY_TAG_TYPE, outgoing_direction) == TRUE) {
        return KERN_SUCCESS;
    }
    
	if (ntohs(iph->ip_len) < (sizeof(struct ip) + sizeof(struct tcphdr) + MIN_HTTP_REQUEST_LEN)) {
		return KERN_SUCCESS;
	}
    
	if (iph->ip_p == IPPROTO_TCP) {
        
		tcph = (struct tcphdr*)((char*)iph + iph->ip_hl * 4);
		
		if (!(tcph->th_flags & TH_PUSH)) {
			return KERN_SUCCESS;
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
    struct connection_block *cb = kn_find_connection_block_with_socket_in_list(so);
    if (cb != NULL) {
        kn_debug("cb: 0x%X is about to be removed and freed\n", cb);
        kn_remove_connection_block_from_list(cb);
        kn_free_connection_block(cb);
    }
}

void kn_sflt_notify_fn (void *cookie, socket_t so, sflt_event_t event, void *param)
{
	if (event == sock_evt_connected) {
		kn_debug("notified that so 0x%X has connected.\n", so);
	}
    else if (event == sock_evt_disconnecting || event == sock_evt_shutdown || event == sock_evt_disconnected || event == sock_evt_closing) {
        char *state = NULL;
        switch (event) {
            case sock_evt_disconnecting:
                state = "sock_evt_disconnecting";
                break;
            case sock_evt_shutdown:
                state = "sock_evt_shutdown";
            case sock_evt_disconnected:
                state = "sock_evt_disconnected";
            case sock_evt_closing:
                state = "sock_evt_closing";
            default:
                break;
        }
        kn_debug("detaching socket 0x%X for event %s\n", so, state);
        sflt_detach(so, KERNET_HANDLE);
    }
}

errno_t kn_sflt_data_in_fn (void *cookie,socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
	return KERN_SUCCESS;
}

errno_t kn_sflt_data_out_fn (void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
    // possibly gConnectionBlockListLock has been locked
    if (kn_mbuf_check_tag(data, gidtag, kMY_TAG_TYPE, outgoing_direction) == TRUE) {
        return KERN_SUCCESS;
    }
    
    struct connection_block *cb = kn_find_connection_block_with_socket_in_list(so);
    if (cb == NULL) {
        kn_debug("detaching so 0x%X because no cb found\n", so);
        sflt_detach(so, KERNET_HANDLE);
        return KERN_SUCCESS;
    }
    
    connection_state state = kn_cb_state(cb);
    
    if (state == received_RST || state == RST_timeout) {
        kn_debug("detaching so 0x%X because cb->state = %d\n", so, state);
        sflt_detach(so, KERNET_HANDLE);
        return KERN_SUCCESS;
    }
    else {
        if (kn_mr_packet_delay_enabled_safe()) {
            kn_cb_add_deferred_packet(cb, *data, *control, flags, to);
            kn_debug("cb: 0x%X added deferred packet\n", cb);
        }
        return EJUSTRETURN;
    }
	return KERN_SUCCESS;
}

errno_t kn_sflt_connect_in_fn (void *cookie, socket_t so, const struct sockaddr *from)
{
    kn_debug("detaching so 0x%X in connect_in_fn\n", so);
	sflt_detach(so, KERNET_HANDLE);
	return KERN_SUCCESS;
}

errno_t kn_sflt_connect_out_fn (void *cookie, socket_t so, const struct sockaddr *to)
{
    kn_debug("kn_sflt_connect_out_fn\n");
    
    if (to->sa_family != AF_INET) {
        kn_debug("kn_sflt_connect_out_fn: to->sa_family = %d != AF_INET\n", to->sa_family);
        sflt_detach(so, KERNET_HANDLE);
        return KERN_SUCCESS;
    }
    
    if (kn_shall_apply_kernet_to_host(((struct sockaddr_in*)to)->sin_addr.s_addr, ((struct sockaddr_in*)to)->sin_port) == FALSE) {
        sflt_detach(so, KERNET_HANDLE);
        return KERN_SUCCESS;
    }
    
    struct sockaddr_in from;
    if (sock_getsockname(so, (struct sockaddr*)&from, sizeof(from)) != 0) { 
        kn_debug("sock_getsockname returned error\n");
        return KERN_SUCCESS;
    }
    
    struct connection_block *cb = kn_alloc_connection_block();
    if (cb == NULL) {
        kn_debug("kn_alloc_connection_block returned error\n");
        return KERN_SUCCESS;
    }
    cb->key.saddr = from.sin_addr.s_addr;
    cb->key.daddr = ((struct sockaddr_in*)to)->sin_addr.s_addr;
    cb->key.sport = from.sin_port;
    cb->key.dport = ((struct sockaddr_in*)to)->sin_port;
    cb->socket = so;
    cb->state = just_created;
    
    kn_add_connection_block_to_list(cb);
    
    kn_debug("kn_sflt_connect_out_fn will record connection to %s:%d\n", kn_inet_ntoa_simple(cb->key.daddr), htons(cb->key.dport));
	return KERN_SUCCESS;
}

errno_t kn_filters_initialize()
{
    int retval = 0;
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
    
    return retval;
    
WTF:
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
    return retval;
}

errno_t kn_filters_close()
{
    int retval = 0;
    if (gsfltFilterRegistered == TRUE) {
		retval = sflt_unregister(KERNET_HANDLE);
		if (retval != 0) {
			kn_debug("sflt_unreturned error %d\n", retval);
		}
	}
	
	if (gipFilterRegistered == TRUE) {
		retval = ipf_remove(kn_ipf_ref);
		if (retval != 0) {
			kn_debug("ipf_remove returned error %d\n", retval);
		}
	}
    return retval;
}

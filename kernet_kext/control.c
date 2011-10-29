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

#include "control.h"
#include "kext.h"
#include "ip_range.h"
#include "utils.h"

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

kern_ctl_ref kn_ctl_ref;

boolean_t       gKernCtlRegistered = FALSE;

errno_t kn_control_initialize()
{
    int retval = 0;
    retval = ctl_register(&kn_ctl_reg, &kn_ctl_ref);
	if (retval == 0) {
		kn_debug("ctl_register id 0x%x, ref 0x%x \n", kn_ctl_reg.ctl_id, kn_ctl_ref);
		gKernCtlRegistered = TRUE;
	}
	else
	{
		kn_debug("ctl_register returned error %d\n", retval);
	}
    return retval;
}

errno_t kn_control_close()
{
    int retval = 0;
    if (gKernCtlRegistered == TRUE) {
        retval = ctl_deregister(kn_ctl_ref);
        gKernCtlRegistered = FALSE;
    }
    return retval;
}

errno_t kn_ctl_connect_fn(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
    struct control_block_t* cb;
    errno_t retval = 0;
    
    if (retval != 0) {
        goto FAILURE;
    }
    
    kn_debug("kn_ctl_connect_fn - unit is %d\n", sac->sc_unit);
    cb = (struct control_block_t*)OSMalloc(sizeof(struct control_block_t), gOSMallocTag);
    if (cb == NULL) {
        kn_debug("OSMalloc returned error\n");
        retval = ENOMEM;
        goto FAILURE;
    }
    
    bzero(cb, sizeof(struct control_block_t));
    cb->unit = sac->sc_unit;
    cb->ref = kctlref;
    cb->connected = TRUE;
    
    *unitinfo = cb;
    
    return KERN_SUCCESS;
    
FAILURE:
    if (cb) {
        OSFree(cb, sizeof(struct control_block_t), gOSMallocTag);
    }
    return retval;
}

errno_t kn_ctl_disconnect_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
    struct control_block_t *cb = (struct control_block_t*)unitinfo;
    if (cb == NULL || cb->unit != unit) {
        kn_debug("progma error. disconnecting a unknown control socket\n");
        return KERN_SUCCESS;
    }
    
    OSFree(cb, sizeof(struct control_block_t), gOSMallocTag);
    
    kn_debug("kn_ctl_disconnect_fn - unit is %d\n", unit);
    
    return KERN_SUCCESS;
}

errno_t kn_ctl_getopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len)
{
    return KERN_SUCCESS;
}

errno_t kn_ctl_send_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags)
{
    struct control_block_t *cb = (struct control_block_t*)unitinfo;
    errno_t retval = 0;
    if (cb == NULL || cb->unit != unit) {
        kn_debug("progma error. disconnecting a unknown control socket\n");
        return KERN_SUCCESS;
    }
    
    if ((retval = kn_ctl_parse_request(cb, m)) != 0) {
        kn_debug("kn_ctl_parse_request returned error %d\n", retval); 
        return KERN_SUCCESS; /* nothing we can do! */
    }
    
    return KERN_SUCCESS;
}

errno_t kn_ctl_setopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
    return KERN_SUCCESS;
}

errno_t kn_ctl_parse_request(struct control_block_t *cb, mbuf_t data)
{
    errno_t retval = 0;
    
    long tot_len;
    struct request_t *req;
    u_int16_t expected_len = sizeof(struct request_t);
    char *buf;
        
    buf = mbuf_data(data);
    tot_len = mbuf_len(data);
    
    if (tot_len < expected_len) {
        kn_debug("ctl request too short, expected %d bytes but only %d bytes supplied\n", tot_len, expected_len);
    }
    
    req = (struct request_t*)buf;
    
    if (req->magic != CTL_MAGIC_WORD) {
        kn_debug("magic word 0x%X mismatches\n", req->magic);
        return EBADMSG;
    }
        
    if (req->opt_code == CTL_OPT_APPEND_IP_RANGE) {
        struct append_ip_range_req_t *opt_req;
        ip_range_policy r_policy;

        expected_len += sizeof(struct append_ip_range_req_t);
        
        if (expected_len != tot_len) {
            kn_debug("req->id %d, length %d of request for optcode 0x%X is invalid\n", req->id, tot_len, req->opt_code);
            return EBADMSG;
        }
        
        opt_req = (struct append_ip_range_req_t*)(buf + sizeof(struct request_t));
        
        r_policy = opt_req->policy;
        
        retval = kn_append_ip_range_entry(opt_req->ip, opt_req->netmask_bits, opt_req->port, r_policy);
        if (retval == E_ALREADY_EXIST) {
            kn_debug("req->id %d, optcode 0x%X tried to append existing range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->netmask_bits);
            kn_ctl_send_response(cb, req->id, req->opt_code, E_ALREADY_EXIST);
            return retval;
        }
        if (retval == E_UPDATED) {
            kn_debug("req->id %d, optcode 0x%X updated existing range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->netmask_bits);
            kn_ctl_send_response(cb, req->id, req->opt_code, E_UPDATED);
            return retval;
        }

        else if (retval == 0) {
            kn_debug("req->id %d, optcode 0x%X succeeded appending range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->netmask_bits);
            kn_ctl_send_response(cb, req->id, req->opt_code, E_OKAY);
            return KERN_SUCCESS;
        }
        
    }
    if (req->opt_code == CTL_OPT_REMOVE_IP_RANGE) {
        struct remove_ip_range_req_t *opt_req;
        
        expected_len += sizeof(struct remove_ip_range_req_t);
        
        if (expected_len != tot_len) {
            kn_debug("req->id %d, length %d of request for optcode 0x%X is invalid\n", req->id, tot_len, req->opt_code);
            return EBADMSG;
        }
        
        opt_req = (struct remove_ip_range_req_t*)(buf + sizeof(struct request_t));
        
        retval = kn_remove_ip_range_entry(opt_req->ip, opt_req->netmask_bits, opt_req->port);
        if (retval == E_DONT_EXIT) {
            kn_debug("req->id %d, optcode 0x%X tried to remove non-existing range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->netmask_bits);
            kn_ctl_send_response(cb, req->id, req->opt_code, E_DONT_EXIT);
            return retval;
        }
        
        else if (retval == 0) {
            kn_debug("req->id %d, optcode 0x%X succeeded removing range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->netmask_bits);
            kn_ctl_send_response(cb, req->id, req->opt_code, E_OKAY);
            return KERN_SUCCESS;
        }
    }
    else {
        kn_debug("req->id %d, unknown optcode 0x%X\n", req->id, req->opt_code);
        kn_ctl_send_response(cb, req->id, req->opt_code, E_UNKNOWN_OPT);
    }
    
    return retval;
}

errno_t kn_ctl_send_response(struct control_block_t *cb, u_int32_t req_id, u_int8_t opt_code, u_int32_t status)
{
    errno_t retval = 0;
    struct response_t response;
    
    if (cb == NULL) {
        return ENOTCONN;
    }
    
    response.magic = CTL_MAGIC_WORD;
    response.opt_code = opt_code;
    response.status = status;
    response.id = req_id;
    
    retval = ctl_enqueuedata(cb->ref, cb->unit, &response, sizeof(response), 0);
    if (retval != 0) {
        kn_debug("ctl_enqueuedata returned error %d\n", retval);
        return retval;
    }
    
    return KERN_SUCCESS;
}
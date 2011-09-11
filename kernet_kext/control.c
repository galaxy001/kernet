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

errno_t kn_ctl_connect_fn(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
    struct control_block_t* cb;
    errno_t retval = 0;
    
    lck_rw_lock_shared(gMasterRecordLock);
    if (master_record.cb != NULL) {
        retval = ECONNREFUSED;
    }
    lck_rw_unlock_shared(gMasterRecordLock);
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
    
    lck_rw_lock_exclusive(gMasterRecordLock);
    master_record.cb = cb;
    lck_rw_unlock_exclusive(gMasterRecordLock);

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
    struct control_block_t *cb;
    lck_rw_lock_shared(gMasterRecordLock);
    cb = master_record.cb;
    lck_rw_unlock_shared(gMasterRecordLock);
    if (cb == NULL || cb->unit != unit) {
        kn_debug("progma error. disconnecting a unknown control socket\n");
        return KERN_SUCCESS;
    }
    
    lck_rw_lock_exclusive(gMasterRecordLock);
    master_record.cb = NULL;
    lck_rw_unlock_exclusive(gMasterRecordLock);
    
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
    struct control_block_t *cb;
    errno_t retval = 0;
    lck_rw_lock_shared(gMasterRecordLock);
    cb = master_record.cb;
    lck_rw_unlock_shared(gMasterRecordLock);
    if (cb == NULL || cb->unit != unit) {
        kn_debug("progma error. disconnecting a unknown control socket\n");
        return KERN_SUCCESS;
    }
    
    if ((retval = kn_ctl_parse_request(m)) != 0) {
        kn_debug("kn_ctl_parse_request returned error %d\n", retval); 
        return KERN_SUCCESS; /* nothing we can do! */
    }
    
    return KERN_SUCCESS;
}

errno_t kn_ctl_setopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
    return KERN_SUCCESS;
}

errno_t kn_ctl_parse_request(mbuf_t data)
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
        
        if (opt_req->policy == IP_RANGE_POLICY_APPLY) {
            r_policy = ip_range_apply_kernet;
        }
        else if (opt_req->policy == IP_RANGE_POLICY_IGNORE) {
            r_policy = ip_range_stay_away;
        }
        else {
            kn_debug("req->id %d, progma error. optcode 0x%X, unknown policy 0x%X\n", req->id, req->opt_code, opt_req->policy);
            return EBADMSG;
        }
        
        retval = kn_append_ip_range_entry(opt_req->ip, opt_req->prefix, opt_req->port, r_policy);
        if (retval == E_ALREADY_EXIST) {
            kn_debug("req->id %d, optcode 0x%X tried to append existing range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->prefix);
            kn_ctl_send_response(req->id, req->opt_code, E_ALREADY_EXIST);
            return retval;
        }
        if (retval == E_UPDATED) {
            kn_debug("req->id %d, optcode 0x%X updated existing range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->prefix);
            kn_ctl_send_response(req->id, req->opt_code, E_UPDATED);
            return retval;
        }

        else if (retval == 0) {
            kn_debug("req->id %d, optcode 0x%X succeeded appending range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->prefix);
            kn_ctl_send_response(req->id, req->opt_code, E_OKAY);
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
        
        retval = kn_remove_ip_range_entry(opt_req->ip, opt_req->prefix, opt_req->port);
        if (retval == E_DONT_EXIT) {
            kn_debug("req->id %d, optcode 0x%X tried to remove non-existing range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->prefix);
            kn_ctl_send_response(req->id, req->opt_code, E_DONT_EXIT);
            return retval;
        }
        
        else if (retval == 0) {
            kn_debug("req->id %d, optcode 0x%X succeeded removing range %s:%d\n", req->id, req->opt_code, kn_inet_ntoa_simple(opt_req->ip), opt_req->prefix);
            kn_ctl_send_response(req->id, req->opt_code, E_OKAY);
            return KERN_SUCCESS;
        }
    }
    else {
        kn_debug("req->id %d, unknown optcode 0x%X\n", req->id, req->opt_code);
        kn_ctl_send_response(req->id, req->opt_code, E_UNKNOWN_OPT);
    }
    
    return retval;
}

errno_t kn_ctl_send_response(u_int32_t req_id, u_int8_t opt_code, u_int32_t status)
{
    errno_t retval = 0;
    struct control_block_t *cb;
    struct response_t response;

    lck_rw_lock_shared(gMasterRecordLock);
    cb = master_record.cb;
    lck_rw_unlock_shared(gMasterRecordLock);
    if (cb == NULL) {
        kn_debug("progma error. attempt to send to non-existing client\n");
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
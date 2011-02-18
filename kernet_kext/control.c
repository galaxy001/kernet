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
    
    u_int8_t opt_code = 0;
    u_int32_t req_magic_word;
    u_int32_t req_id;

    u_int16_t tot_len = 0;
    u_int16_t read_len = 0;
    u_int16_t expected_len = sizeof(CTL_MAGIC_WORD) + sizeof(opt_code) + sizeof(req_id);
    char *buf;
    
    tot_len = mbuf_len(data);
    buf = mbuf_data(data);
    
    if (tot_len < expected_len) {
        kn_debug("ctl request too short, expected %d bytes but only %d bytes supplied\n", tot_len, expected_len);
    }
    
    memcpy(&req_magic_word, buf + read_len, sizeof(CTL_MAGIC_WORD));
    read_len += sizeof(CTL_MAGIC_WORD);
    if (req_magic_word != CTL_MAGIC_WORD) {
        kn_debug("magic word 0x%X mismatches\n", req_magic_word);
        return EBADMSG;
    }
    
    memcpy(&req_id, buf + read_len, sizeof(req_id));
    read_len += sizeof(req_id);
    
    memcpy(&opt_code, buf + read_len, sizeof(opt_code));
    read_len += sizeof(opt_code);
    
    if (opt_code == CTL_OPT_APPEND_IP_RANGE) {
        /* (u_int32_t)ip + (u_int8_t)prefix + (u_int8_t)policy */
        
        u_int32_t r_ip;
        u_int8_t r_prefix, r_raw_policy;
        ip_range_policy r_policy;
        expected_len += sizeof(r_ip) + sizeof(r_policy) + sizeof(r_prefix);
        
        if (expected_len != tot_len) {
            kn_debug("req_id %d, length %d of request for optcode 0x%X is invalid\n", req_id, opt_code, tot_len);
            return EBADMSG;
        }
        
        memcpy(&r_ip, buf + read_len, sizeof(r_ip));
        read_len += sizeof(r_ip);
        
        memcpy(&r_policy, buf + read_len, sizeof(r_policy));
        read_len += sizeof(r_policy);
        
        memcpy(&r_raw_policy, buf + read_len, sizeof(r_raw_policy));
        read_len += sizeof(r_raw_policy);
        
        if (read_len != tot_len) {
            kn_debug("req_id %d, progma error. optcode 0x%X, read %d bytes, less than supplied\n", req_id, opt_code, read_len);
            return EPROTO;
        }
        
        if (r_raw_policy == 0xA1) {
            r_policy = ip_range_apply_kernet;
        }
        else if (r_raw_policy == 0xA2) {
            r_policy = ip_range_stay_away;
        }
        else {
            kn_debug("req_id %d, progma error. optcode 0x%X, unknown policy\n", req_id, opt_code);
            return EBADMSG;
        }
        
        retval = kn_append_ip_range_entry(r_ip, r_prefix, r_policy);
        if (retval == E_ALREADY_EXIST) {
            kn_debug("req_id %d, optcode 0x%X tried to append existing range %s:%d\n", req_id, opt_code, kn_inet_ntoa(r_ip), r_prefix);
            kn_ctl_send_response(req_id, opt_code, E_ALREADY_EXIST);
            return retval;
        }
        else if (retval == 0) {
            kn_debug("req_id %d, optcode 0x%X succeeded appending range %s:%d\n", req_id, opt_code, kn_inet_ntoa(r_ip), r_prefix);
            kn_ctl_send_response(req_id, opt_code, E_OKAY);
            return KERN_SUCCESS;
        }
        
    }
    else {
        kn_debug("req_id %d, unknown optcode 0x%X\n", req_id, opt_code);
        kn_ctl_send_response(req_id, opt_code, E_UNKNOWN_OPT);
    }
    
    return retval;
}

errno_t kn_ctl_send_response(u_int32_t req_id, u_int8_t opt_code, u_int32_t status)
{
    char buf[256];
    errno_t retval = 0;
    u_int32_t written_len = 0;
    static const u_int32_t magic_word = CTL_MAGIC_WORD;
    struct control_block_t *cb;

    lck_rw_lock_shared(gMasterRecordLock);
    cb = master_record.cb;
    lck_rw_unlock_shared(gMasterRecordLock);
    if (cb == NULL) {
        kn_debug("progma error. attempt to send to non-existing client\n");
        return ENOTCONN;
    }
    
    memcpy(buf + written_len, &magic_word, sizeof(magic_word));
    written_len += sizeof(magic_word);
    memcpy(buf + written_len, &req_id, sizeof(req_id));
    written_len += sizeof(req_id);
    memcpy(buf + written_len, &opt_code, sizeof(opt_code));
    written_len += sizeof(opt_code);
    memcpy(buf + written_len, &status, sizeof(status));
    written_len += sizeof(status);
    
    retval = ctl_enqueuedata(cb->ref, cb->unit, buf, written_len, 0);
    if (retval != 0) {
        kn_debug("ctl_enqueuedata returned error %d\n", retval);
        return retval;
    }
    
    return KERN_SUCCESS;
}
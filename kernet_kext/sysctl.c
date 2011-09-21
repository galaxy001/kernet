#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include "utils.h"
#include "sysctl.h"
#include "mr.h"

//            #define SYSCTL_HANDLER_ARGS (struct sysctl_oid *oidp, void *arg1, int arg2, \
//            struct sysctl_req *req)
//
//
//            /*
//             * This describes the access space for a sysctl request.  This is needed
//             * so that we can use the interface from the kernel or from user-space.
//             */
//            struct sysctl_req {
//                struct proc	*p;
//                int		lock;
//                user_addr_t	oldptr;		/* pointer to user supplied buffer */
//                size_t		oldlen;		/* user buffer length (also returned) */
//                size_t		oldidx;		/* total data iteratively copied out */
//                int		(*oldfunc)(struct sysctl_req *, const void *, size_t);
//                user_addr_t	newptr;		/* buffer containing new value */
//                size_t		newlen;		/* length of new value */
//                size_t		newidx;		/* total data iteratively copied in */
//                int		(*newfunc)(struct sysctl_req *, void *, size_t);
//            };
//
//            SLIST_HEAD(sysctl_oid_list, sysctl_oid);
//
//            #define SYSCTL_OID_VERSION	1	/* current OID structure version */
//
//            /*
//             * This describes one "oid" in the MIB tree.  Potentially more nodes can
//             * be hidden behind it, expanded by the handler.
//             *
//             * NOTES:	We implement binary comparibility between CTLFLAG_OID2 and
//             *		pre-CTLFLAG_OID2 structure in sysctl_register_oid() and in
//             *		sysctl_unregister_oid() using the fact that the fields up
//             *		to oid_fmt are unchanged, and that the field immediately
//             *		following is on an alignment boundary following a pointer
//             *		type and is also a pointer.  This lets us get the previous
//             *		size of the structure, and the copy-cut-off point, using
//             *		the offsetof() language primitive, and these values  are
//             *		used in conjunction with the fact that earlier and future
//             *		statically compiled sysctl_oid structures are declared via
//             *		macros.  This lets us overload the macros so that the addition
//             *		of the CTLFLAG_OID2 in newly compiled code containing sysctl
//             *		node declarations, subsequently allowing us to to avoid
//             *		changing the KPI used for non-static (un)registration in
//             *		KEXTs.
//             *
//             *		This depends on the fact that people declare SYSCTLs,
//             *		rather than declaring sysctl_oid structures.  All new code
//             *		should avoid declaring struct sysctl_oid's directly without
//             *		the macros; the current risk for this is limited to losing
//             *		your description field and ending up with a malloc'ed copy,
//             *		as if it were a legacy binary static declaration via SYSCTL;
//             *		in the future, we may deprecate access to a named structure
//             *		type in third party code.  Use the macros, or our code will
//             *		end up with compile errors when that happens.
//             *
//             *		Please try to include a long description of the field in any
//             *		new sysctl declarations (all the macros support this).  This
//             *		field may be the only human readable documentation your users
//             *		get for your sysctl.
//             */
//            struct sysctl_oid {
//                struct sysctl_oid_list *oid_parent;
//                SLIST_ENTRY(sysctl_oid) oid_link;
//                int		oid_number;
//                int		oid_kind;
//                void		*oid_arg1;
//                int		oid_arg2;
//                const char	*oid_name;
//                int 		(*oid_handler) SYSCTL_HANDLER_ARGS;
//                const char	*oid_fmt;
//                const char	*oid_descr; /* offsetof() field / long description */
//                int		oid_version;
//                int		oid_refcnt;
//            };


struct sysctl_oid_list sysctl__net_kernet_children;
static int kn_sysctl_handler SYSCTL_HANDLER_ARGS;

SYSCTL_DECL(_net_kernet);
SYSCTL_NODE(_net, OID_AUTO, kernet, CTLFLAG_RW, NULL, "Kernet Controls");
SYSCTL_PROC(_net_kernet, OID_AUTO, packet_delay_enabled, CTLTYPE_INT|CTLFLAG_RW, 0, 0, &kn_sysctl_handler, "I", "");
SYSCTL_PROC(_net_kernet, OID_AUTO, injection_enabled , CTLTYPE_INT|CTLFLAG_RW, 0, 0, &kn_sysctl_handler, "I", "");
SYSCTL_PROC(_net_kernet, OID_AUTO, RST_detection_enabled, CTLTYPE_INT|CTLFLAG_RW, 0, 0, &kn_sysctl_handler, "I", "");
SYSCTL_PROC(_net_kernet, OID_AUTO, watchdog_enabled, CTLTYPE_INT|CTLFLAG_RW, 0, 0, &kn_sysctl_handler, "I", "");
SYSCTL_PROC(_net_kernet, OID_AUTO, fake_DNS_response_dropping_enabled, CTLTYPE_INT|CTLFLAG_RW, 0, 0, &kn_sysctl_handler, "I", "");
SYSCTL_PROC(_net_kernet, OID_AUTO, RST_timeout, CTLTYPE_INT|CTLFLAG_RW, 0, 0, &kn_sysctl_handler, "I", "");


errno_t kn_register_sysctls()
{
    sysctl_register_oid(&sysctl__net_kernet);
    sysctl_register_oid(&sysctl__net_kernet_packet_delay_enabled);
    sysctl_register_oid(&sysctl__net_kernet_injection_enabled);
    sysctl_register_oid(&sysctl__net_kernet_RST_detection_enabled);
    sysctl_register_oid(&sysctl__net_kernet_watchdog_enabled);
    sysctl_register_oid(&sysctl__net_kernet_fake_DNS_response_dropping_enabled);
    sysctl_register_oid(&sysctl__net_kernet_RST_timeout);
    return 0;
}

errno_t kn_unregister_sysctls() {
    sysctl_unregister_oid(&sysctl__net_kernet_packet_delay_enabled);
    sysctl_unregister_oid(&sysctl__net_kernet_injection_enabled);
    sysctl_unregister_oid(&sysctl__net_kernet_RST_detection_enabled);
    sysctl_unregister_oid(&sysctl__net_kernet_watchdog_enabled);
    sysctl_unregister_oid(&sysctl__net_kernet_fake_DNS_response_dropping_enabled);
    sysctl_unregister_oid(&sysctl__net_kernet_RST_timeout);
    sysctl_unregister_oid(&sysctl__net_kernet);
    return 0;
}

int kn_sysctl_handler SYSCTL_HANDLER_ARGS {
    int error = 0, out;
    
    kn_debug("oidp->oid_name: %s\n", oidp->oid_name);
    
    if (req->newptr) {
        /* Write request */
        
        if (oidp == &sysctl__net_kernet_packet_delay_enabled) {
            if (CAST_PTR_INT(req->newptr) == 0 || CAST_PTR_INT(req->newptr) == 1) {
                kn_mr_set_packet_delay_enabled_safe(CAST_PTR_INT(req->newptr));
            }
            else {
                kn_debug("new value %d should only be either 0 or 1\n", CAST_PTR_INT(req->newptr));
                error = EINVAL; 
            }
        }
        
        else if (oidp == &sysctl__net_kernet_fake_DNS_response_dropping_enabled) {
            if (CAST_PTR_INT(req->newptr) == 0 || CAST_PTR_INT(req->newptr) == 1) {
                kn_mr_set_fake_DNS_response_dropping_enabled_safe(CAST_PTR_INT(req->newptr));
            }
            else {
                kn_debug("new value %d should only be either 0 or 1\n", CAST_PTR_INT(req->newptr));
                error = EINVAL; 
            }
        }
        
        else if (oidp == &sysctl__net_kernet_injection_enabled) {
            if (CAST_PTR_INT(req->newptr) == 0 || CAST_PTR_INT(req->newptr) == 1) {
                kn_mr_set_injection_enabled_safe(CAST_PTR_INT(req->newptr));
            }
            else {
                kn_debug("new value %d should only be either 0 or 1\n", CAST_PTR_INT(req->newptr));
                error = EINVAL; 
            }
        }
        
        else if (oidp == &sysctl__net_kernet_RST_detection_enabled) {
            if (CAST_PTR_INT(req->newptr) == 0 || CAST_PTR_INT(req->newptr) == 1) {
                kn_mr_set_RST_detection_enabled_safe(CAST_PTR_INT(req->newptr));
            }
            else {
                kn_debug("new value %d should only be either 0 or 1\n", CAST_PTR_INT(req->newptr));
                error = EINVAL; 
            }
        }
        
        else if (oidp == &sysctl__net_kernet_RST_timeout) {
            if (IN_RANGE(CAST_PTR_INT(req->newptr), 0, 5000)) {   /* limit to 0ms ~ 5000ms */
                kn_mr_set_RST_timeout_safe(CAST_PTR_INT(req->newptr));
            }
            else {
                kn_debug("new value %d should only be either 0 or 5000\n", CAST_PTR_INT(req->newptr));
                error = EINVAL; 
            }
        }
        
        else if (oidp == &sysctl__net_kernet_watchdog_enabled) {
            if (CAST_PTR_INT(req->newptr) == 0 || CAST_PTR_INT(req->newptr) == 1) {
                kn_mr_set_watchdog_enabled_safe(CAST_PTR_INT(req->newptr));
            }
            else {
                kn_debug("new value %d should only be either 0 or 1\n", CAST_PTR_INT(req->newptr));
                error = EINVAL; 
            }
        }
        
        else {
            kn_debug("unknown oidp->oid_name: %s\n", oidp->oid_name);
            error = EINVAL; 
        }
    } else {
        /* Read request */
        
        if (oidp == &sysctl__net_kernet_packet_delay_enabled) {
            out = kn_mr_packet_delay_enabled_safe();
            error = SYSCTL_OUT(req, &out, sizeof out);
        }
        
        else if (oidp == &sysctl__net_kernet_injection_enabled) {
            out = kn_mr_injection_enabled_safe();
            error = SYSCTL_OUT(req, &out, sizeof out);
        }
        
        else if (oidp == &sysctl__net_kernet_fake_DNS_response_dropping_enabled) {
            out = kn_mr_fake_DNS_response_dropping_enabled_safe();
            error = SYSCTL_OUT(req, &out, sizeof out);
        }
        
        else if (oidp == &sysctl__net_kernet_watchdog_enabled) {
            out = kn_mr_watchdog_enabled_safe();
            error = SYSCTL_OUT(req, &out, sizeof out);
        }
        
        else if (oidp == &sysctl__net_kernet_RST_detection_enabled) {
            out = kn_mr_RST_detection_enabled_safe();
            error = SYSCTL_OUT(req, &out, sizeof out);
        }
        
        else if (oidp == &sysctl__net_kernet_RST_timeout) {
            out = kn_mr_RST_timeout_safe();
            error = SYSCTL_OUT(req, &out, sizeof out);
        }
        
        else {
            kn_debug("unknown oidp->oid_name: %s\n", oidp->oid_name);
            error = EINVAL; 
        }
    }
    /* In any case, return success or return the reason for failure  */
    return error;
}

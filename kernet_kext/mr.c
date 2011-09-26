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

#include "locks.h"
#include "mr.h"
#include "connection.h"
#include "utils.h"
#include "kext.h"

struct master_record_t master_record;

errno_t kn_mr_initialize()
{
    errno_t ret = 0;
    
    bzero(&master_record, sizeof(master_record));
    master_record.RST_timeout = 400;
    master_record.injection_enabled = FALSE;
    master_record.RST_detection_enabled = FALSE;
    master_record.watchdog_enabled = FALSE;
    master_record.packet_delay_enabled = FALSE;
    master_record.fake_DNS_response_dropping_enabled = FALSE;
 
    master_record.packet_delay_enabled_lock = lck_mtx_alloc_init(gMutexGroup, gGlobalLocksAttr);
	if (master_record.packet_delay_enabled_lock == NULL)
	{
		kn_debug("lck_grp_alloc_init returned error\n");
		ret |= ENOMEM;
        return ret;
	}
    
    master_record.RST_timeout_lock = lck_mtx_alloc_init(gMutexGroup, gGlobalLocksAttr);
	if (master_record.RST_timeout_lock == NULL)
	{
		kn_debug("lck_grp_alloc_init returned error\n");
		ret |= ENOMEM;
        return ret;
	}
    master_record.RST_detection_enabled_lock = lck_mtx_alloc_init(gMutexGroup, gGlobalLocksAttr);
	if (master_record.RST_detection_enabled_lock == NULL)
	{
		kn_debug("lck_grp_alloc_init returned error\n");
		ret |= ENOMEM;
        return ret;
	}
    master_record.watchdog_enabled_lock = lck_mtx_alloc_init(gMutexGroup, gGlobalLocksAttr);
	if (master_record.watchdog_enabled_lock == NULL)
	{
		kn_debug("lck_grp_alloc_init returned error\n");
		ret |= ENOMEM;
        return ret;
	}
    master_record.fake_DNS_response_dropping_enabled_lock = lck_mtx_alloc_init(gMutexGroup, gGlobalLocksAttr);
	if (master_record.fake_DNS_response_dropping_enabled_lock == NULL)
	{
		kn_debug("lck_grp_alloc_init returned error\n");
		ret |= ENOMEM;
        return ret;
	}
    master_record.injection_enabled_lock = lck_mtx_alloc_init(gMutexGroup, gGlobalLocksAttr);
	if (master_record.injection_enabled_lock == NULL)
	{
		kn_debug("lck_grp_alloc_init returned error\n");
		ret |= ENOMEM;
        return ret;
	}

    return ret;
}

errno_t kn_mr_close()
{
    errno_t ret = 0;
    lck_mtx_free(master_record.injection_enabled_lock, gMutexGroup);
    lck_mtx_free(master_record.fake_DNS_response_dropping_enabled_lock, gMutexGroup);
    lck_mtx_free(master_record.watchdog_enabled_lock, gMutexGroup);
    lck_mtx_free(master_record.RST_detection_enabled_lock, gMutexGroup);
    lck_mtx_free(master_record.RST_timeout_lock, gMutexGroup);
    lck_mtx_free(master_record.packet_delay_enabled_lock, gMutexGroup);
    return ret;
}

boolean_t kn_mr_injection_enabled()
{
    boolean_t ret;
    ret = master_record.injection_enabled;
    return ret;
}

boolean_t kn_mr_RST_detection_enabled()
{
    boolean_t ret;
    ret = master_record.RST_detection_enabled;
    return ret;
}

boolean_t kn_mr_watchdog_enabled()
{
    boolean_t ret;
    ret = master_record.watchdog_enabled;
    return ret;
}

boolean_t kn_mr_packet_delay_enabled()
{
    boolean_t ret;
    ret = master_record.packet_delay_enabled;
    return ret;
}

boolean_t kn_mr_fake_DNS_response_dropping_enabled()
{
    boolean_t ret;
    ret = master_record.fake_DNS_response_dropping_enabled;
    return ret;
}

u_int16_t kn_mr_RST_timeout()
{
    u_int16_t ret;
    ret = master_record.RST_timeout;
    return ret;
}

boolean_t kn_mr_injection_enabled_safe()
{
    boolean_t ret;
    lck_mtx_lock(master_record.injection_enabled_lock);
    ret = kn_mr_injection_enabled();
    lck_mtx_unlock(master_record.injection_enabled_lock);
    return ret;
}

boolean_t kn_mr_RST_detection_enabled_safe()
{
    boolean_t ret;
    lck_mtx_lock(master_record.RST_detection_enabled_lock);
    ret = kn_mr_RST_detection_enabled();
    lck_mtx_unlock(master_record.RST_detection_enabled_lock);
    return ret;
}

boolean_t kn_mr_watchdog_enabled_safe()
{
    boolean_t ret;
    lck_mtx_lock(master_record.watchdog_enabled_lock);
    ret = kn_mr_watchdog_enabled();
    lck_mtx_unlock(master_record.watchdog_enabled_lock);
    return ret;
}

boolean_t kn_mr_packet_delay_enabled_safe()
{
    boolean_t ret;
    lck_mtx_lock(master_record.packet_delay_enabled_lock);
    ret = kn_mr_packet_delay_enabled();
    lck_mtx_unlock(master_record.packet_delay_enabled_lock);
    return ret;
}

boolean_t kn_mr_fake_DNS_response_dropping_enabled_safe()
{
    boolean_t ret;
    lck_mtx_lock(master_record.fake_DNS_response_dropping_enabled_lock);
    ret = kn_mr_fake_DNS_response_dropping_enabled();
    lck_mtx_unlock(master_record.fake_DNS_response_dropping_enabled_lock);
    return ret;
    
}

u_int16_t kn_mr_RST_timeout_safe()
{
    u_int16_t ret;
    lck_mtx_lock(master_record.RST_timeout_lock);
    ret = kn_mr_RST_timeout();
    lck_mtx_unlock(master_record.RST_timeout_lock);
    return ret;
}

void kn_mr_set_injection_enabled(boolean_t enabled)
{
    master_record.injection_enabled = enabled;
}

void kn_mr_set_watchdog_enabled(boolean_t enabled)
{
    boolean_t cur = kn_mr_watchdog_enabled();
    if (cur == enabled)
        goto END;
    else {
        master_record.watchdog_enabled = enabled;
        if (enabled) {
            kn_register_deferred_packet_watchdog();
        }
        else {
            kn_unregister_deferred_packet_watchdog();
        }
    }
END:
    return;
}

void kn_mr_set_RST_detection_enabled(boolean_t enabled)
{
    master_record.RST_detection_enabled = enabled;
}

void kn_mr_set_packet_delay_enabled(boolean_t enabled)
{
    boolean_t cur = master_record.packet_delay_enabled;
    if (cur == enabled)
        goto END;
    else {
        master_record.packet_delay_enabled = enabled;
        if (enabled == FALSE) {
            /* reinject any swallowed packet beforing disabling it */
            lck_mtx_lock(gConnectionBlockListLock);
            kn_reinject_all_deferred_packets_for_all();
            lck_mtx_unlock(gConnectionBlockListLock);
        }
    }
END:
    return;
}

void kn_mr_set_RST_timeout(u_int16_t timeout)
{
    master_record.RST_timeout = timeout;
}

void kn_mr_set_fake_DNS_response_dropping_enabled(boolean_t enabled)
{
    master_record.fake_DNS_response_dropping_enabled = enabled;
}

void kn_mr_enable_default_services()
{
    kn_debug("kn_mr_enable_default_services\n");
    kn_mr_set_injection_enabled_safe(TRUE);
    kn_mr_set_fake_DNS_response_dropping_enabled_safe(TRUE);
    kn_mr_set_packet_delay_enabled_safe(TRUE);
    kn_mr_set_watchdog_enabled_safe(TRUE);
    kn_mr_set_RST_detection_enabled_safe(TRUE);
}

void kn_mr_disable_all_services()
{
    kn_debug("kn_mr_disable_all_services\n");
    kn_mr_set_injection_enabled_safe(FALSE);
    kn_mr_set_fake_DNS_response_dropping_enabled_safe(FALSE);
    kn_mr_set_packet_delay_enabled_safe(FALSE);
    kn_mr_set_watchdog_enabled_safe(FALSE);
    kn_mr_set_RST_detection_enabled_safe(FALSE);
}

void kn_mr_set_injection_enabled_safe(boolean_t enabled)
{
    lck_mtx_lock(master_record.injection_enabled_lock);
    kn_mr_set_injection_enabled(enabled);
    lck_mtx_unlock(master_record.injection_enabled_lock);
}

void kn_mr_set_watchdog_enabled_safe(boolean_t enabled)
{
    lck_mtx_lock(master_record.watchdog_enabled_lock);
    kn_mr_set_watchdog_enabled(enabled);
    lck_mtx_unlock(master_record.watchdog_enabled_lock);
}

void kn_mr_set_RST_detection_enabled_safe(boolean_t enabled)
{
    lck_mtx_lock(master_record.RST_detection_enabled_lock);
    kn_mr_set_RST_detection_enabled(enabled);
    lck_mtx_unlock(master_record.RST_detection_enabled_lock);
}

void kn_mr_set_RST_timeout_safe(u_int16_t timeout)
{
    lck_mtx_lock(master_record.RST_timeout_lock);
    kn_mr_set_RST_timeout(timeout);
    lck_mtx_unlock(master_record.RST_timeout_lock);
}

void kn_mr_set_packet_delay_enabled_safe(boolean_t enabled)
{
    lck_mtx_lock(master_record.packet_delay_enabled_lock);
    kn_mr_set_packet_delay_enabled(enabled);
    lck_mtx_unlock(master_record.packet_delay_enabled_lock);
}

void kn_mr_set_fake_DNS_response_dropping_enabled_safe(boolean_t enabled)
{
    lck_mtx_lock(master_record.fake_DNS_response_dropping_enabled_lock);
    kn_mr_set_fake_DNS_response_dropping_enabled(enabled);
    lck_mtx_unlock(master_record.fake_DNS_response_dropping_enabled_lock);
}


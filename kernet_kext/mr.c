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

struct master_record_t master_record;

void kn_mr_initialize()
{
    bzero(&master_record, sizeof(master_record));
    master_record.RST_timeout = 400;
    master_record.injection_enabled = FALSE;
    master_record.RST_detection_enabled = FALSE;
    master_record.watchdog_enabled = FALSE;
    master_record.packet_delay_enabled = FALSE;
    master_record.fake_DNS_response_dropping_enabled = FALSE;
}

boolean_t kn_mr_injection_enabled()
{
    boolean_t ret;
    kn_lock_shared_master_record();
    ret = master_record.injection_enabled;
    kn_unlock_shared_master_record();
    return ret;
}

boolean_t kn_mr_RST_detection_enabled()
{
    boolean_t ret;
    kn_lock_shared_master_record();
    ret = master_record.RST_detection_enabled;
    kn_unlock_shared_master_record();
    return ret;
}

boolean_t kn_mr_watchdog_enabled()
{
    boolean_t ret;
    kn_lock_shared_master_record();
    ret = master_record.watchdog_enabled;
    kn_unlock_shared_master_record();
    return ret;
}

boolean_t kn_mr_packet_delay_enabled()
{
    boolean_t ret;
    kn_lock_shared_master_record();
    ret = master_record.packet_delay_enabled;
    kn_unlock_shared_master_record();
    return ret;
}

boolean_t kn_mr_fake_DNS_response_dropping_enabled()
{
    boolean_t ret;
    kn_lock_shared_master_record();
    ret = master_record.fake_DNS_response_dropping_enabled;
    kn_unlock_shared_master_record();
    return ret;
}

u_int16_t kn_mr_RST_timeout()
{
    u_int16_t ret;
    kn_lock_shared_master_record();
    ret = master_record.RST_timeout;
    kn_unlock_shared_master_record();
    return ret;
}

void kn_mr_set_injection_enabled(boolean_t enabled)
{
    kn_lock_exclusive_master_record();
    master_record.injection_enabled = enabled;
    kn_unlock_exclusive_master_record();
}

void kn_mr_set_watchdog_enabled(boolean_t enabled)
{
    boolean_t cur = kn_mr_watchdog_enabled();
    if (cur == enabled)
        goto END;
    else {
        kn_lock_exclusive_master_record();
        master_record.watchdog_enabled = enabled;
        kn_unlock_exclusive_master_record();
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
    kn_lock_exclusive_master_record();
    master_record.RST_detection_enabled = enabled;
    kn_unlock_exclusive_master_record();
}

void kn_mr_set_packet_delay_enabled(boolean_t enabled)
{
    boolean_t cur = master_record.packet_delay_enabled;
    if (cur == enabled)
        goto END;
    else {
        kn_lock_exclusive_master_record();
        master_record.packet_delay_enabled = enabled;
        kn_unlock_exclusive_master_record();
        if (enabled == FALSE) {
            /* reinject any swallowed packet beforing disabling it */
            kn_reinject_all_deferred_packets_for_all();
        }
    }
END:
    return;
}

void kn_mr_set_RST_timeout(u_int16_t timeout)
{
    kn_lock_exclusive_master_record();
    master_record.RST_timeout = timeout;
    kn_unlock_exclusive_master_record();
    return;
}

void kn_mr_set_fake_DNS_response_dropping_enabled(boolean_t enabled)
{
    kn_lock_exclusive_master_record();
    master_record.fake_DNS_response_dropping_enabled = enabled;
    kn_unlock_exclusive_master_record();
}

void kn_mr_enable_default_services()
{
    kn_debug("kn_mr_enable_default_services\n");
    kn_mr_set_injection_enabled(TRUE);
    kn_mr_set_fake_DNS_response_dropping_enabled(TRUE);
    kn_mr_set_packet_delay_enabled(TRUE);
    kn_mr_set_watchdog_enabled(TRUE);
}

void kn_mr_disable_all_services()
{
    kn_debug("kn_mr_disable_all_services\n");
    kn_mr_set_injection_enabled(FALSE);
    kn_mr_set_fake_DNS_response_dropping_enabled(FALSE);
    kn_mr_set_packet_delay_enabled(FALSE);
    kn_mr_set_watchdog_enabled(FALSE);
}
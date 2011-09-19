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

OSMallocTag		gOSMallocTag;
mbuf_tag_id_t	gidtag;

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
    
    retval = kn_ip_range_initialize();
    if (retval != 0)
	{
		kn_debug("kn_ip_range_initialize returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_connection_initialize();
    if (retval != 0)
	{
		kn_debug("kn_connection_initialize returned error %d\n", retval);
		goto WTF;
	}
    
	retval = mbuf_tag_id_find(KERNET_BUNDLEID , &gidtag);
	if (retval != 0)
	{
		kn_debug("mbuf_tag_id_find returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_filters_initialize();
    if (retval != 0)
	{
		kn_debug("kn_filters_initialize returned error %d\n", retval);
		goto WTF;
	}
	
    retval = kn_control_initialize();
    if (retval != 0)
	{
		kn_debug("kn_control_initialize returned error %d\n", retval);
		goto WTF;
	}
    
    kn_mr_enable_default_services();
    
    kn_dirty_test();
        
	kn_debug("extension has been loaded.\n");
    return KERN_SUCCESS;
	
WTF:
    kn_filters_close();
    
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
        
    retval = kn_connection_close();
    if (retval != 0)
	{
		kn_debug("kn_connection_initialize returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_ip_range_close();
    if (retval != 0)
	{
		kn_debug("kn_ip_range_initialize returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_filters_close();
    if (retval != 0)
	{
		kn_debug("kn_filters_close returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_control_close();
    if (retval != 0)
	{
		kn_debug("kn_control_close returned error %d\n", retval);
		goto WTF;
	}
    
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

void kn_dirty_test() {
}

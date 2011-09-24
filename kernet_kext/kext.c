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
#include <kern/clock.h>

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
#include "sysctl.h"

OSMallocTag		gOSMallocTag;
mbuf_tag_id_t	gidtag;

kern_return_t com_ccp0101_kext_kernet_start (kmod_info_t * ki, void * d) {
	
	int retval = 0;
	
	gOSMallocTag = OSMalloc_Tagalloc(KERNET_BUNDLEID, OSMT_DEFAULT); // don't want the flag set to OSMT_PAGEABLE since
	// it would indicate that the memory was pageable.
	if (gOSMallocTag == NULL)
        goto WTF;	
        
    retval = kn_alloc_locks();
    if (retval != 0)
	{
		kn_debug("kn_alloc_locks returned error %d\n", retval);
		goto WTF;
	}
        
    retval = kn_mr_initialize();
    if (retval != 0)
	{
		kn_debug("kn_mr_initialize returned error %d\n", retval);
		goto WTF;
	}
    
    kn_register_sysctls();
    
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
    
    kn_mr_disable_all_services();
    
    kn_msleep(2000, "kernet_shutdown", "kernet shutting down...");
    
    retval = kn_connection_close();
    if (retval != 0)
	{
		kn_debug("kn_connection_initialize returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_filters_close();
    if (retval != 0)
	{
		kn_debug("kn_filters_close returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_ip_range_close();
    if (retval != 0)
	{
		kn_debug("kn_ip_range_initialize returned error %d\n", retval);
		goto WTF;
	}
    
    retval = kn_control_close();
    if (retval != 0)
	{
		kn_debug("kn_control_close returned error %d\n", retval);
		goto WTF;
	}
    
    kn_unregister_sysctls();
    
    retval = kn_mr_close();
    if (retval != 0)
	{
		kn_debug("kn_mr_close returned error %d\n", retval);
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

void kn_dirty_test() {
}

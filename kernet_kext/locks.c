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
#include "utils.h"

lck_rw_t *gMasterRecordLock = NULL;
lck_mtx_t *gDelayedInjectQueueLock = NULL;
lck_rw_t *gipRangeListLock = NULL;
lck_grp_t *gMutexGroup = NULL;
lck_mtx_t *gConnectionBlockListLock = NULL;
lck_grp_attr_t *gMutexGroupAttr = NULL;
lck_attr_t *gGlobalLocksAttr = NULL;
lck_attr_t *gConnectionBlockLocksAttr = NULL;

errno_t kn_alloc_locks()
{
	errno_t			result = 0;
    
    gMutexGroupAttr = lck_grp_attr_alloc_init();
    lck_grp_attr_setstat(gMutexGroupAttr);
    
    gGlobalLocksAttr = lck_attr_alloc_init();
    gConnectionBlockLocksAttr = lck_attr_alloc_init();

    kn_locks_enable_debug();
    
    result |= kn_alloc_mutex_group();
    result |= kn_alloc_master_record_lock();
    result |= kn_alloc_ip_range_list_lock();
    result |= kn_alloc_connection_block_list_lock();
    
    return result;
}

void kn_locks_enable_debug()
{
    lck_attr_setdebug(gConnectionBlockLocksAttr);
    lck_attr_setdebug(gGlobalLocksAttr);
}

void kn_locks_disable_debug()
{
    lck_attr_setdefault(gConnectionBlockLocksAttr);
    lck_attr_setdefault(gGlobalLocksAttr);
}

errno_t kn_alloc_mutex_group()
{
    errno_t			result = 0;
    assert(gMutexGroup == NULL);

	gMutexGroup = lck_grp_alloc_init(KERNET_BUNDLEID, gMutexGroupAttr);
	if (gMutexGroup == NULL)
	{
		kn_debug("lck_grp_alloc_init returned error\n");
		result = ENOMEM;
	}
    return result;
}

errno_t kn_alloc_master_record_lock()
{
    errno_t result = 0;
    assert(gMutexGroup == NULL);
    assert(gMasterRecordLock == NULL);
    
    gMasterRecordLock = lck_rw_alloc_init(gMutexGroup, gGlobalLocksAttr);
    if (gMasterRecordLock == NULL)
    {
        kn_debug("lck_mtx_alloc_init returned error\n");
        result = ENOMEM;
    }
    return result;
}

errno_t kn_alloc_ip_range_list_lock()
{
    errno_t result = 0;
    assert(gMutexGroup == NULL);
    assert(gipRangeListLock == NULL);
    
    gipRangeListLock = lck_rw_alloc_init(gMutexGroup, gGlobalLocksAttr);
    if (gipRangeListLock == NULL)
    {
        kn_debug("lck_mtx_alloc_init returned error\n");
        result = ENOMEM;
    }
    return result;
}

errno_t kn_alloc_connection_block_list_lock()
{
    errno_t result = 0;
    assert(gMutexGroup == NULL);
    assert(gConnectionBlockListLock == NULL);
    
    gConnectionBlockListLock = lck_mtx_alloc_init(gMutexGroup, gGlobalLocksAttr);
    if (gConnectionBlockListLock == NULL)
    {
        kn_debug("lck_mtx_alloc_init returned error\n");
        result = ENOMEM;
    }
    return result;
}

void kn_free_mutex_group()
{
    assert(gMutexGroup);
    lck_grp_free(gMutexGroup);
    gMutexGroup = NULL;
}

void kn_free_master_record_lock()
{
    assert(gMutexGroup);
    assert(gMasterRecordLock);
    lck_rw_free(gMasterRecordLock, gMutexGroup);
    gMasterRecordLock = NULL;
}

void kn_free_ip_range_list_lock()
{
    assert(gMutexGroup);
    assert(gipRangeListLock);
    lck_rw_free(gipRangeListLock, gMutexGroup);
    gipRangeListLock = NULL;
}

void kn_free_connection_block_list_lock()
{
    assert(gMutexGroup);
    assert(gConnectionBlockListLock);
    lck_mtx_free(gConnectionBlockListLock, gMutexGroup);
    gConnectionBlockListLock = NULL;
}

errno_t kn_free_locks()
{	
 	if (gipRangeListLock)
	{
        kn_free_ip_range_list_lock();
	}
    if (gConnectionBlockListLock) {
        kn_free_connection_block_list_lock();
    }
    if (gMasterRecordLock) 
    {
        kn_free_master_record_lock();
    }
    if (gMutexGroup) {
        kn_free_mutex_group();
    }
    
    lck_grp_attr_free(gMutexGroupAttr);
    lck_attr_free(gGlobalLocksAttr);
    lck_attr_free(gConnectionBlockLocksAttr);
    return 0;
}

void kn_lock_shared_master_record() { 
    lck_rw_lock_shared(gMasterRecordLock); 
}
void kn_unlock_shared_master_record() { 
    lck_rw_unlock_shared(gMasterRecordLock); 
}
void kn_lock_exclusive_master_record() { 
    lck_rw_lock_exclusive(gMasterRecordLock); 
}
void kn_unlock_exclusive_master_record() { 
    lck_rw_unlock_exclusive(gMasterRecordLock); 
}

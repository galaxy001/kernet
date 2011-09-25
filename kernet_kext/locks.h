//
//  locks.h
//  kernet
//
//  Created by Mike Chen on 9/16/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef LOCKS_H
#define LOCKS_H

__private_extern__ lck_rw_t *gMasterRecordLock;
__private_extern__ lck_rw_t *gipRangeListLock;
__private_extern__ lck_grp_t *gMutexGroup;
__private_extern__ lck_mtx_t *gConnectionBlockListLock;
__private_extern__ lck_grp_attr_t *gMutexGroupAttr;
__private_extern__ lck_attr_t *gGlobalLocksAttr;
__private_extern__ lck_attr_t *gConnectionBlockLocksAttr;

errno_t kn_alloc_locks();
errno_t kn_free_locks();

errno_t kn_alloc_mutex_group();
errno_t kn_alloc_master_record_lock();
errno_t kn_alloc_ip_range_list_lock();
errno_t kn_alloc_connection_block_list_lock();

void kn_free_mutex_group();
void kn_free_master_record_lock();
void kn_free_ip_range_list_lock();
void kn_free_connection_block_list_lock();

inline void kn_lock_shared_master_record() { lck_rw_lock_shared(gMasterRecordLock); };
inline void kn_unlock_shared_master_record() { lck_rw_unlock_shared(gMasterRecordLock); };
inline void kn_lock_exclusive_master_record() { lck_rw_lock_exclusive(gMasterRecordLock); };
inline void kn_unlock_exclusive_master_record() { lck_rw_unlock_exclusive(gMasterRecordLock); };

void kn_locks_enable_debug();
void kn_locks_disable_debug();

#endif

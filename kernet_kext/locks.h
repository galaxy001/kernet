//
//  locks.h
//  kernet
//
//  Created by Mike Chen on 9/16/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef LOCKS_H
#define LOCKS_H

extern lck_rw_t *gMasterRecordLock;
extern lck_rw_t *gipRangeListLock;
extern lck_grp_t *gMutexGroup;
extern lck_mtx_t *gConnectionBlockListLock;
extern lck_grp_attr_t *gMutexGroupAttr;
extern lck_attr_t *gGlobalLocksAttr;
extern lck_attr_t *gConnectionBlockLocksAttr;

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

void kn_lock_shared_master_record();
void kn_unlock_shared_master_record();
void kn_lock_exclusive_master_record();
void kn_unlock_exclusive_master_record();

void kn_locks_enable_debug();
void kn_locks_disable_debug();

#endif

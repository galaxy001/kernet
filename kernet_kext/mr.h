//
//  mr.h
//  kernet
//
//  Created by Mike Chen on 9/19/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef MR_H
#define MR_H

#include <mach/mach_types.h>
#include <kern/locks.h>

struct master_record_t {
    boolean_t packet_delay_enabled;
    lck_mtx_t *packet_delay_enabled_lock;
    boolean_t injection_enabled;
    lck_mtx_t *injection_enabled_lock;
    boolean_t RST_detection_enabled;
    lck_mtx_t *RST_detection_enabled_lock;
    boolean_t watchdog_enabled;
    lck_mtx_t *watchdog_enabled_lock;
    boolean_t fake_DNS_response_dropping_enabled;
    lck_mtx_t *fake_DNS_response_dropping_enabled_lock;
    u_int16_t RST_timeout;
    lck_mtx_t *RST_timeout_lock;
};

__private_extern__ struct master_record_t master_record;

errno_t kn_mr_initialize();
errno_t kn_mr_close();

boolean_t kn_mr_injection_enabled();
boolean_t kn_mr_RST_detection_enabled();
boolean_t kn_mr_watchdog_enabled();
boolean_t kn_mr_packet_delay_enabled();
boolean_t kn_mr_fake_DNS_response_dropping_enabled();
u_int16_t kn_mr_RST_timeout();

boolean_t kn_mr_injection_enabled_safe();
boolean_t kn_mr_RST_detection_enabled_safe();
boolean_t kn_mr_watchdog_enabled_safe();
boolean_t kn_mr_packet_delay_enabled_safe();
boolean_t kn_mr_fake_DNS_response_dropping_enabled_safe();
u_int16_t kn_mr_RST_timeout_safe();

void kn_mr_set_injection_enabled(boolean_t enabled);
void kn_mr_set_watchdog_enabled(boolean_t enabled);
void kn_mr_set_RST_detection_enabled(boolean_t enabled);
void kn_mr_set_RST_timeout(u_int16_t timeout);
void kn_mr_set_packet_delay_enabled(boolean_t enabled);
void kn_mr_set_fake_DNS_response_dropping_enabled(boolean_t enabled);

void kn_mr_set_injection_enabled_safe(boolean_t enabled);
void kn_mr_set_watchdog_enabled_safe(boolean_t enabled);
void kn_mr_set_RST_detection_enabled_safe(boolean_t enabled);
void kn_mr_set_RST_timeout_safe(u_int16_t timeout);
void kn_mr_set_packet_delay_enabled_safe(boolean_t enabled);
void kn_mr_set_fake_DNS_response_dropping_enabled_safe(boolean_t enabled);

void kn_mr_enable_default_services();
void kn_mr_disable_all_services();

#endif

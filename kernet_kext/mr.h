//
//  mr.h
//  kernet
//
//  Created by Mike Chen on 9/19/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef MR_H
#define MR_H

struct master_record_t {
    boolean_t packet_delay_enabled;
    boolean_t injection_enabled;
    boolean_t RST_detection_enabled;
    boolean_t watchdog_enabled;
    boolean_t fake_DNS_response_dropping_enabled;
    u_int16_t RST_timeout;
};

extern struct master_record_t master_record;

void kn_mr_initialize();
boolean_t kn_mr_injection_enabled();
boolean_t kn_mr_RST_detection_enabled();
boolean_t kn_mr_watchdog_enabled();
boolean_t kn_mr_packet_delay_enabled();
boolean_t kn_mr_fake_DNS_response_dropping_enabled();
u_int16_t kn_mr_RST_timeout();

void kn_mr_set_injection_enabled(boolean_t enabled);
void kn_mr_set_watchdog_enabled(boolean_t enabled);
void kn_mr_set_RST_detection_enabled(boolean_t enabled);
void kn_mr_set_RST_timeout(u_int16_t timeout);
void kn_mr_set_packet_delay_enabled(boolean_t enabled);
void kn_mr_set_fake_DNS_response_dropping_enabled(boolean_t enabled);

void kn_mr_enable_default_services();
void kn_mr_disable_all_services();

#endif

#ifndef KEXT_H
#define KEXT_H

#ifndef KERNET_KEXT
#error Private header for kernet kernel extension!
#endif

#include "common.h"

struct dnshdr
{
	char d1[4];
	u_int16_t ques_num;
	u_int16_t ans_num;
	u_int16_t auth_rrs;
	u_int16_t addi_rrs;
};

typedef enum _packet_direction {
    outgoing_direction = 1,
    incoming_direction = 2,
} packet_direction;


struct control_block_t {						
	kern_ctl_ref		ref;		// control reference to the connected process
	u_int32_t			unit;		// unit number associated with the connected process
	boolean_t			connected;
    TAILQ_ENTRY(control_block)  link;
};

struct master_record_t {
    boolean_t packet_delay_enabled;
    boolean_t injection_enabled;
    boolean_t RST_detection_enabled;
    boolean_t watchdog_enabled;
    boolean_t fake_DNS_response_dropping_enabled;
    u_int16_t RST_timeout;
};

extern ipfilter_t kn_ipf_ref;
extern mbuf_tag_id_t gidtag;
extern kern_ctl_ref gctl_ref;
extern OSMallocTag gOSMallocTag;

extern struct ip_range_list ip_range_list;
extern struct master_record_t master_record;

void kn_dirty_test();

// master record operations:
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

#endif /* KEXT_H */
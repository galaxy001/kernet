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

// control socket operations:


#endif /* KEXT_H */
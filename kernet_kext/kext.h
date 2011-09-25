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

extern ipfilter_t kn_ipf_ref;
extern mbuf_tag_id_t gidtag;
extern kern_ctl_ref gctl_ref;
extern OSMallocTag gOSMallocTag;
extern boolean_t gShuttingDown;

extern struct ip_range_list ip_range_list;

void kn_dirty_test();


#endif /* KEXT_H */
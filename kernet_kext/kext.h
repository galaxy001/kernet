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

__private_extern__ ipfilter_t kn_ipf_ref;
__private_extern__ mbuf_tag_id_t gidtag;
__private_extern__ kern_ctl_ref gctl_ref;
__private_extern__ OSMallocTag gOSMallocTag;
__private_extern__ boolean_t gShuttingDown;

__private_extern__ struct ip_range_list ip_range_list;

void kn_dirty_test();


#endif /* KEXT_H */
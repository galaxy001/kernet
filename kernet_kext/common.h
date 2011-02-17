#ifndef COMMON_H
#define COMMON_H

#define KERNET_BUNDLEID "com.ccp0101.kext.kernet"
#define KERNET_HANDLE 0x01306A15 

#define ETHHDR_LEN 14
#define MIN_HTTP_REQUEST_LEN 14
#define kMY_TAG_TYPE 1
#define CTL_MAGIC_WORD 0x012A7715

#define CTL_OPT_APPEND_IP_RANGE 0x10

/* CTL general */
#define E_OKAY 1
#define E_PROGMA 9
#define E_UNKNOWN_OPT 10
/* CTL_OPT_APPEND_IP_RANGE : kn_append_ip_range_entry */
#define E_ALREADY_EXIST 11

#endif /* COMMON_H */
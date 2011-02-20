#ifndef COMMON_H
#define COMMON_H

#define KERNET_BUNDLEID "com.ccp0101.kext.kernet"
#define KERNET_HANDLE 0x01306A15 

#define ETHHDR_LEN 14
#define MIN_HTTP_REQUEST_LEN 14
#define kMY_TAG_TYPE 1
#define CTL_MAGIC_WORD 0x012A7715

#define CTL_OPT_APPEND_IP_RANGE 0x10
#define CTL_OPT_REMOVE_IP_RANGE 0x11

#define IP_RANGE_POLICY_APPLY 0xA1
#define IP_RANGE_POLICY_IGNORE 0xA2

/* CTL general */
#define E_OKAY 1
#define E_PROGMA 9
#define E_UNKNOWN_OPT 10
/* CTL_OPT_APPEND_IP_RANGE : kn_append_ip_range_entry */
#define E_ALREADY_EXIST 11
#define E_UPDATED 12
/* CTL_OPT_REMOVE_IP_RANGE : kn_remove_ip_range_entry */
#define E_DONT_EXIT 13

struct request_t {
    u_int32_t magic;
    u_int32_t id;
    u_int8_t opt_code;
};

struct append_ip_range_req_t {
    u_int32_t ip;
    u_int8_t prefix;
    u_int8_t policy;
};

struct remove_ip_range_req_t {
    u_int32_t ip;
    u_int8_t prefix;
};

struct response_t {
    u_int32_t magic;
    u_int32_t id;
    u_int8_t opt_code;
    u_int32_t status;
};

#endif /* COMMON_H */
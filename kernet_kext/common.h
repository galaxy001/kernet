//
//  common.h
//  kernet
//
//  Created by Mike Chen on 9/17/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef COMMON_H
#define COMMON_H

#define KERNET_BUNDLEID "com.ccp0101.kext.kernet"
#define KERNET_HANDLE 0x01306A15 

#define ETHHDR_LEN 14
#define MIN_HTTP_REQUEST_LEN 14
#define kMY_TAG_TYPE 1

#define READABLE_IPv4_LENGTH 4*sizeof"123"

#define BUILD_FOR_DEBUGGING

#define CTL_MAGIC_WORD 0x012A7715

#define CTL_OPT_APPEND_IP_RANGE 0x10
#define CTL_OPT_REMOVE_IP_RANGE 0x11

/* CTL general */
#define E_OKAY 0
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
    u_int8_t netmask_bits;
    u_int16_t port; 
    u_int8_t policy;
}; // should in network byte order

struct remove_ip_range_req_t {
    u_int32_t ip;
    u_int8_t netmask_bits;
    u_int16_t port; 
};

struct response_t {
    u_int32_t magic;
    u_int32_t id;
    u_int8_t opt_code;
    u_int32_t status;
};

typedef enum _ip_range_policy {
	ip_range_direct = 0, 
    ip_range_kernet_1 = 1,
    ip_range_kernet_2 = 2,
    ip_range_kernet_3 = 3,
    ip_range_kernet_4 = 4,
    ip_range_kernet_experiment = 100,
} ip_range_policy;

#endif

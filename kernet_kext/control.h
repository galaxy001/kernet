#ifndef CONTROL_H
#define CONTROL_H

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

errno_t kn_control_initialize();
errno_t kn_control_close();

errno_t kn_ctl_connect_fn(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo);
errno_t kn_ctl_disconnect_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);  
errno_t kn_ctl_getopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);  
errno_t kn_ctl_send_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags);
errno_t kn_ctl_setopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);
errno_t kn_ctl_parse_request(mbuf_t data);
errno_t kn_ctl_send_response(u_int32_t req_id, u_int8_t opt_code, u_int32_t status);

#endif /* CONTROL_H */
#ifndef KERNET_H
#define KERNET_H

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

typedef enum _ip_range_policy {
	ip_range_apply_kernet = 1, 
	ip_range_stay_away = 2,
} ip_range_policy;

typedef enum _packet_irection {
    outgoing_direction = 1,
    incoming_direction = 2,
} packet_direction;

struct ip_range_entry {
	u_int32_t	ip;
	u_int8_t	prefix;
    u_int16_t port;
	ip_range_policy	policy;
	
	TAILQ_ENTRY(ip_range_entry) link;
};

struct delayed_inject_entry {
    mbuf_t pkt;
    struct timeval timestamp;
    u_int32_t timeout; 
    packet_direction direction;
    TAILQ_ENTRY(delayed_inject_entry) link;
};

struct control_block_t {						
	kern_ctl_ref		ref;		// control reference to the connected process
	u_int32_t			unit;		// unit number associated with the connected process
	boolean_t			connected;
    TAILQ_ENTRY(control_block)  link;
};

struct master_record_t {
    struct control_block_t *cb;
    u_int16_t http_delay_ms;
};

extern ipfilter_t kn_ipf_ref;
extern mbuf_tag_id_t gidtag;
extern kern_ctl_ref gctl_ref;
extern OSMallocTag gOSMallocTag;
extern lck_rw_t *gMasterRecordLock;

extern struct ip_range_queue ip_range_queue;
extern struct delayed_inject_queue delayed_inject_queue;
extern struct master_record_t master_record;

// utils:
char* kn_inet_ntoa(u_int32_t ina);
void kn_debug (const char *fmt, ...);
u_int16_t kn_tcp_sum_calc(u_int16_t len_tcp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[]);
boolean_t kn_mbuf_check_tag(mbuf_t *m, mbuf_tag_id_t module_id, mbuf_tag_type_t tag_type, packet_direction value);
errno_t	kn_mbuf_set_tag(mbuf_t *data, mbuf_tag_id_t id_tag, mbuf_tag_type_t tag_type, packet_direction value);
errno_t kn_prepend_mbuf_hdr(mbuf_t *data, size_t pkt_len);

// master record operations:
void kn_mr_initialize();

// control socket operations:
errno_t kn_ctl_connect_fn(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo);
errno_t kn_ctl_disconnect_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);  
errno_t kn_ctl_getopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);  
errno_t kn_ctl_send_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags);
errno_t kn_ctl_setopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);
errno_t kn_ctl_parse_request(mbuf_t data);
errno_t kn_ctl_send_response(u_int32_t req_id, u_int8_t opt_code, u_int32_t status);

// ip filter callbacks: 
errno_t kn_ip_input_fn (void *cookie, mbuf_t *data, int offset, u_int8_t protocol);
errno_t kn_ip_output_fn (void *cookie, mbuf_t *data, ipf_pktopts_t options);

// socket filter callbacks: 
void kn_sflt_unregistered_fn (sflt_handle handle);
errno_t kn_sflt_attach_fn (void **cookie, socket_t so); 
void kn_sflt_detach_fn (void *cookie, socket_t so);
void kn_sflt_notify_fn (void *cookie, socket_t so, sflt_event_t event, void *param);
errno_t kn_sflt_connect_in_fn (void *cookie, socket_t so, const struct sockaddr *from);
errno_t kn_sflt_connect_out_fn (void *cookie, socket_t so, const struct sockaddr *to);
errno_t kn_sflt_data_in_fn (void *cookie,socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);  
errno_t kn_sflt_data_out_fn (void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);  

// ip range:
boolean_t kn_shall_apply_kernet_to_host(u_int32_t ip, u_int16_t port);
errno_t kn_append_ip_range_entry(u_int32_t ip, u_int8_t prefix, u_int16_t port, ip_range_policy policy);
errno_t kn_append_ip_range_entry_default_ports(u_int32_t ip, u_int8_t prefix, ip_range_policy policy);
errno_t kn_remove_ip_range_entry(u_int32_t ip, u_int8_t prefix, u_int16_t port);
errno_t kn_remove_ip_range_entry_default_ports(u_int32_t ip, u_int8_t prefix);
void kn_fulfill_ip_ranges();

// manipulator: 
errno_t kn_inject_after_synack (mbuf_t incm_data);
errno_t kn_inject_after_http (mbuf_t otgn_data);

// injection: 
errno_t kn_tcp_pkt_from_params(mbuf_t *data, u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, const char* payload, size_t payload_len);
errno_t kn_inject_tcp_from_params(u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, const char* payload, size_t payload_len, packet_direction direction);

// resource alloc/dealloc:
errno_t kn_alloc_locks();
errno_t kn_free_locks();
errno_t kn_alloc_queues();
errno_t kn_free_queues();

// delayed packet injection: 
errno_t kn_delay_pkt_inject(mbuf_t pkt, u_int32_t ms, packet_direction direction);
boolean_t kn_delayed_inject_entry_in_queue(struct delayed_inject_entry* entry);
void kn_delayed_inject_timeout(void* param);

#endif /* KERNET_H */
#ifndef KERNET_H
#define KERNET_H

#define KERNET_BUNDLEID "com.ccp0101.kext.kernet"
#define KERNET_HANDLE 0x01306A15 

#define ETHHDR_LEN 14
#define MIN_HTTP_REQUEST_LEN 14

struct dnshdr
{
	char d1[4];
	u_int16_t ques_num;
	u_int16_t ans_num;
	u_int16_t auth_rrs;
	u_int16_t addi_rrs;
};

typedef enum _ip_range_policy {
	ip_range_apply_kernet, 
	ip_range_stay_away, 
} ip_range_policy;

typedef enum _inject_direction {
    outgoing_direction, 
    incoming_direction, 
} inject_direction;

struct ip_range_entry {
	u_int32_t	ip;
	u_int8_t	prefix;
	ip_range_policy	policy;
	
	TAILQ_ENTRY(ip_range_entry) entries;
};

struct delayed_inject_entry {
    mbuf_t pkt;
    struct timeval timestamp;
    u_int32_t timeout; 
    inject_direction direction;
    TAILQ_ENTRY(delayed_inject_entry) entries;
};

extern ipfilter_t kn_ipf_ref;

// utils:
extern char* kn_inet_ntoa(u_int32_t ina);
extern void kn_debug (const char *fmt, ...);
extern u_int16_t kn_tcp_sum_calc(u_int16_t len_tcp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[]);

// ip filter callbacks: 
extern errno_t kn_ip_input_fn (void *cookie, mbuf_t *data, int offset, u_int8_t protocol);
extern errno_t kn_ip_output_fn (void *cookie, mbuf_t *data, ipf_pktopts_t options);

// socket filter callbacks: 
extern void kn_sflt_unregistered_fn (sflt_handle handle);
extern errno_t kn_sflt_attach_fn (void **cookie, socket_t so); 
extern void kn_sflt_detach_fn (void *cookie, socket_t so);
extern void kn_sflt_notify_fn (void *cookie, socket_t so, sflt_event_t event, void *param);
extern errno_t kn_sflt_connect_in_fn (void *cookie, socket_t so, const struct sockaddr *from);
extern errno_t kn_sflt_connect_out_fn (void *cookie, socket_t so, const struct sockaddr *to);
extern errno_t kn_sflt_data_in_fn (void *cookie,socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);  
extern errno_t kn_sflt_data_out_fn (void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);  

// ip range:
extern boolean_t kn_shall_apply_kernet_to_ip(u_int32_t ip);
extern errno_t kn_append_ip_range_entry(u_int32_t ip, u_int8_t prefix, ip_range_policy policy);
extern void kn_fulfill_ip_ranges();

// manipulator: 
extern errno_t kn_inject_after_synack (mbuf_t incm_data);
extern errno_t kn_inject_after_http (mbuf_t otgn_data);

// injection: 
extern errno_t kn_tcp_pkt_from_params(mbuf_t *data, u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, const char* payload, size_t payload_len);
extern errno_t kn_inject_tcp_from_params(u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, const char* payload, size_t payload_len, inject_direction direction);

extern errno_t kn_alloc_locks();
extern errno_t kn_free_locks();
extern errno_t kn_alloc_queues();
extern errno_t kn_free_queues();

// delayed packet injection: 
extern errno_t kn_delay_pkt_inject(mbuf_t pkt, u_int32_t ms, inject_direction direction);
extern boolean_t kn_delayed_inject_entry_in_queue(struct delayed_inject_entry* entry);
extern void kn_delayed_inject_timeout(void* param);

#endif /* KERNET_H */
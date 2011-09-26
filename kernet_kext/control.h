#ifndef CONTROL_H
#define CONTROL_H

struct control_block_t {						
	kern_ctl_ref		ref;		// control reference to the connected process
	u_int32_t			unit;		// unit number associated with the connected process
	boolean_t			connected;
    TAILQ_ENTRY(control_block)  link;
};

errno_t kn_control_initialize();
errno_t kn_control_close();

errno_t kn_ctl_connect_fn(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo);
errno_t kn_ctl_disconnect_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);  
errno_t kn_ctl_getopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);  
errno_t kn_ctl_send_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags);
errno_t kn_ctl_setopt_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);
errno_t kn_ctl_parse_request(struct control_block_t *cb, mbuf_t data);
errno_t kn_ctl_send_response(struct control_block_t *cb, u_int32_t req_id, u_int8_t opt_code, u_int32_t status);

#endif /* CONTROL_H */
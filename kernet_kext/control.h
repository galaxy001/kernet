#ifndef CONTROL_H
#define CONTROL_H

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
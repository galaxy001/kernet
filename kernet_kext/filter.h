//
//  filter.h
//  kernet
//
//  Created by Mike Chen on 9/17/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef FILTER_H
#define FILTER_H

errno_t kn_filters_initialize();
errno_t kn_filters_close();

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


#endif

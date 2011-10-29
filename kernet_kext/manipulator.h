//
//  manipulator.h
//  kernet
//
//  Created by Mike Chen on 9/17/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef MANIPULATOR_H
#define MANIPULATOR_H

#include "ip_range.h"

typedef errno_t (*kn_synack_injection_func)(mbuf_t incm_data);  

boolean_t kn_mbuf_check_tag(mbuf_t *m, mbuf_tag_id_t module_id, mbuf_tag_type_t tag_type, packet_direction value);
errno_t	kn_mbuf_set_tag(mbuf_t *data, mbuf_tag_id_t id_tag, mbuf_tag_type_t tag_type, packet_direction value);
errno_t kn_prepend_mbuf_hdr(mbuf_t *data, size_t pkt_len);

errno_t kn_inject_after_synack_strict(mbuf_t incm_data);
errno_t kn_inject_after_synack_1 (mbuf_t incm_data);
errno_t kn_inject_after_synack_2 (mbuf_t incm_data);
errno_t kn_inject_after_synack_3 (mbuf_t incm_data);
errno_t kn_inject_after_synack_experiment (mbuf_t incm_data);
kn_synack_injection_func kn_synack_injection_function_for_ip_range_policy(ip_range_policy policy);

errno_t kn_tcp_pkt_from_params(mbuf_t *data, u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, u_int16_t tcph_win, const char* payload, size_t payload_len);
errno_t kn_inject_tcp_from_params(u_int8_t tcph_flags, u_int32_t iph_saddr, u_int32_t iph_daddr, u_int16_t tcph_sport, u_int16_t tcph_dport, u_int32_t tcph_seq, u_int32_t tcph_ack, u_int16_t tcph_win, const char* payload, size_t payload_len, packet_direction direction);
errno_t kn_set_ip_ttl(mbuf_t *data, u_int8_t ttl);
errno_t kn_inject_after_http (mbuf_t otgn_data);
#endif

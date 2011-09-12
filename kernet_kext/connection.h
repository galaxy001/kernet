//
//  connection.h
//  kernet
//
//  Created by Mike Chen on 9/11/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef CONNECTION_H
#define CONNECTION_H

#include "utlist.h"

typedef enum _connection_state {
    just_created = 1,
    injected_RST = 2,
    received_RST = 3, 
} connection_state;

struct connection_key {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
};

struct deferred_packet {
    mbuf_t data;
    mbuf_t control;
    sflt_data_flag_t flags;
    struct sockaddr to;
    struct deferred_packet *next, *prev;
};

struct connection_block {
    struct connection_key key;
    socket_t socket;
    lck_mtx_t *lock;
    connection_state state;
    struct deferred_packet *deferred_packet_queue;
	TAILQ_ENTRY(connection_block) link;
};

extern lck_mtx_t *gConnectionBlockListLock;
extern struct connection_block_list connection_block_list;

void kn_alloc_connection_block_list();
void kn_free_connection_block_list();
struct connection_block* kn_find_connection_block_with_address_in_list(u_int32_t saddr, u_int32_t daddr, u_int32_t sport, u_int32_t dport);
struct connection_block* kn_find_connection_block_with_socket_in_list(socket_t so);
void kn_remove_connection_block_from_list(struct connection_block *b);
void kn_add_connection_block_to_list(struct connection_block *b);
void kn_move_connection_block_to_tail(struct connection_block *b);

void kn_print_connection_block(struct connection_block* b);
struct connection_block* kn_alloc_connection_block();
void kn_free_connection_block(struct connection_block* b);

errno_t kn_cb_add_deferred_packet(struct connection_block* cb, mbuf_t data, mbuf_t control, sflt_data_flag_t flags, const struct sockaddr *to);
errno_t kn_reinject_deferred_packet(socket_t so, struct deferred_packet *p);
errno_t kn_cb_reinject_deferred_packets(struct connection_block *cb);


#endif

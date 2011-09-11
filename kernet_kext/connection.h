//
//  connection.h
//  kernet
//
//  Created by Mike Chen on 9/11/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef CONNECTION_H
#define CONNECTION_H

struct connection_key {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
};

struct connection_block {
    struct connection_key key;
    lck_mtx_t *lock;
	TAILQ_ENTRY(connection_block) link;
};

extern struct connection_block_list connection_block_list;

void kn_alloc_connection_block_list();
void kn_free_connection_block_list();
struct connection_block* kn_find_connection_block_in_list(u_int32_t saddr, u_int32_t daddr, u_int32_t sport, u_int32_t dport);
void kn_remove_connection_block_from_list(struct connection_block *b);
void kn_add_connection_block_to_list(struct connection_block *b);
void kn_move_connection_block_to_tail(struct connection_block *b);

void kn_print_connection_block(struct connection_block* b);
struct connection_block* kn_alloc_connection_block();
void kn_free_connection_block(struct connection_block* b);

#endif

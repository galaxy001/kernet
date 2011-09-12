#include <mach/mach_types.h>
#include <mach/vm_types.h>

#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <netinet/kpi_ipfilter.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>
#include <net/kpi_interface.h>
#include <sys/kpi_socketfilter.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/debug.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>
#include <sys/kern_control.h>
#include <sys/kauth.h>
#include <sys/time.h>
#include <stdarg.h>
#include <sys/queue.h>

#include "kext.h"
#include "connection.h"

TAILQ_HEAD(connection_block_list, connection_block);
struct connection_block_list connection_block_list;

void kn_alloc_connection_block_list() {
    TAILQ_INIT(&connection_block_list);
}

void kn_free_connection_block_list()
{
    struct connection_block *b, *tmp;
    TAILQ_FOREACH_SAFE(b, &connection_block_list, link, tmp) {
        TAILQ_REMOVE(&connection_block_list, b, link);
        kn_free_connection_block(b);
    }
}

void kn_add_connection_block_to_list(struct connection_block *b)
{
    TAILQ_INSERT_TAIL(&connection_block_list, b, link);
    kn_debug("kn_add_connection_block_to_list\n");
    kn_print_connection_block(b);
}

void kn_remove_connection_block_from_list(struct connection_block *b)
{
    TAILQ_REMOVE(&connection_block_list, b, link);
}

struct connection_block* kn_find_connection_block_with_address_in_list(u_int32_t saddr, u_int32_t daddr, u_int32_t sport, u_int32_t dport)
{
    char s_addr[READABLE_IPv4_LENGTH];
    char d_addr[READABLE_IPv4_LENGTH];

    struct connection_block *b = NULL;
    boolean_t found = FALSE;
    TAILQ_FOREACH_REVERSE(b, &connection_block_list, connection_block_list, link) {
        // currently source addresses don't match so ignore them for now
        //  && b->key.sport == sport && b->key.saddr == saddr
        
        if (b->key.daddr == daddr && b->key.dport == dport) {
            found = TRUE;
            break;
        }
    }
    if (found) {
        kn_debug("found via address: ");
        kn_print_connection_block(b);
        return b;
    }
    else {
        kn_debug("failed connection block for %s:%d <-> %s:%d\n", kn_inet_ntoa(saddr, s_addr), sport, daddr, kn_inet_ntoa(daddr, d_addr));
        return NULL;
    }
}

struct connection_block* kn_find_connection_block_with_socket_in_list(socket_t so)
{
    struct connection_block *b = NULL;
    boolean_t found = FALSE;
    TAILQ_FOREACH_REVERSE(b, &connection_block_list, connection_block_list, link) {
        if (b->socket == so) {
            found = TRUE;
            break;
        }
    }
    if (found) {
        kn_debug("found via socket: ");
        kn_print_connection_block(b);
        return b;
    }
    else {
        kn_debug("failed connection block for socket 0x%X", so);
        return NULL;
    }
}

void kn_move_connection_block_to_tail(struct connection_block *b)
{
    TAILQ_REMOVE(&connection_block_list, b, link);
    TAILQ_INSERT_TAIL(&connection_block_list, b, link);
}

struct connection_block* kn_alloc_connection_block()
{
    struct connection_block *b;
    
    b = (struct connection_block*)OSMalloc(sizeof(struct connection_block), gOSMallocTag);
    if (b == NULL) {
        kn_debug("OSMalloc returned error\n");
        return NULL;
    }
    bzero(b, sizeof(struct connection_block));
    
    b->lock = lck_mtx_alloc_init(gMutexGroup, LCK_ATTR_NULL);
    if (b->lock == NULL)
    {
        kn_debug("lck_mtx_alloc_init returned error\n");
        goto FAILURE;
    }

    TAILQ_INIT(&b->deferred_packet_queue);
    
    return b;
    
FAILURE:
    OSFree(b, sizeof(*b), gOSMallocTag);
    return NULL;
}

void kn_free_connection_block(struct connection_block* b)
{
    lck_mtx_free(b->lock, gMutexGroup);
    
    struct deferred_packet *p;
    TAILQ_FOREACH(p, &b->deferred_packet_queue, link) {
        TAILQ_REMOVE(&b->deferred_packet_queue, p, link);
        mbuf_free(p->data);
        mbuf_free(p->control);
        OSFree(p, sizeof(struct deferred_packet), gOSMallocTag);
    }
    
    OSFree(b, sizeof(struct connection_block), gOSMallocTag);
}

void kn_print_connection_block(struct connection_block* b)
{
    char saddr[READABLE_IPv4_LENGTH];
    char daddr[READABLE_IPv4_LENGTH];
    
    kn_debug("connection block of socket 0x%X for %s:%d <-> %s:%d\n", b->socket, kn_inet_ntoa(b->key.saddr, saddr), htons(b->key.sport), kn_inet_ntoa(b->key.daddr, daddr), htons(b->key.dport));
    
    return;
}

errno_t kn_cb_add_deferred_packet(struct connection_block* cb, mbuf_t data, mbuf_t control, sflt_data_flag_t flags, const struct sockaddr *to)
{
    struct deferred_packet *p = (struct deferred_packet*)OSMalloc(sizeof(struct deferred_packet), gOSMallocTag);
    if (p == NULL) {
        kn_debug("OSMalloc returned error\n");
        return ENOMEM;
    }
    
    p->data = data;
    p->control = control;
    p->flags = flags;
    memcpy(&p->to, &to, sizeof(struct sockaddr_in));
    
    TAILQ_INSERT_TAIL(&cb->deferred_packet_queue, p, link);
    
    return KERN_SUCCESS;
}

errno_t kn_cb_reinject_deferred_packets(struct connection_block* cb)
{
    struct deferred_packet *p, *tmp;
    int retval = 0, ret = 0;
    
    TAILQ_FOREACH_SAFE(p, &cb->deferred_packet_queue, link, tmp) {
        TAILQ_REMOVE(&cb->deferred_packet_queue, p, link);
        retval = sock_inject_data_out(cb->socket, &p->to, p->data, p->control, p->flags);
        if (retval != 0) {
            ret = retval;
            kn_debug("sock_inject_data_out returned error %d\n", retval);
        }
        OSFree(p, sizeof(struct deferred_packet), gOSMallocTag);
    }
    return ret;
}




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
}

void kn_remove_connection_block_from_list(struct connection_block *b)
{
    TAILQ_REMOVE(&connection_block_list, b, link);
}

struct connection_block* kn_find_connection_block_in_list(u_int32_t saddr, u_int32_t daddr, u_int32_t sport, u_int32_t dport)
{
    struct connection_block *b = NULL;
    boolean_t found = FALSE;
    TAILQ_FOREACH_REVERSE(b, &connection_block_list, connection_block_list, link) {
        if (b->key.daddr == daddr && b->key.dport == dport && b->key.sport == sport && b->key.saddr == saddr) {
            found = TRUE;
            break;
        }
    }
    if (found) return b;
    else return NULL;
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

    return b;
    
FAILURE:
    OSFree(b, sizeof(*b), gOSMallocTag);
    return NULL;
}

void kn_free_connection_block(struct connection_block* b)
{
    lck_mtx_free(b->lock, gMutexGroup);
    OSFree(b, sizeof(struct connection_block), gOSMallocTag);
}

void kn_print_connection_block(struct connection_block* b)
{
    char saddr[READABLE_IPv4_LENGTH];
    char daddr[READABLE_IPv4_LENGTH];
    
    kn_debug("connection block for %s:%d <-> %s:%d\n", kn_inet_ntoa(b->key.saddr, saddr), htons(b->key.sport), kn_inet_ntoa(b->key.saddr, daddr), htons(b->key.dport));
    
    return;
}
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
#include "locks.h"
#include "utils.h"
#include "manipulator.h"
#include "mr.h"

TAILQ_HEAD(connection_block_list, connection_block);
struct connection_block_list connection_block_list;

errno_t kn_connection_initialize()
{
    kn_alloc_connection_block_list();
    return 0;
}

errno_t kn_connection_close()
{
    kn_free_connection_block_list();
    return 0;
}

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
    lck_mtx_lock(gConnectionBlockListLock);
    TAILQ_INSERT_TAIL(&connection_block_list, b, link);
    lck_mtx_unlock(gConnectionBlockListLock);
    kn_debug("kn_add_connection_block_to_list\n");
    kn_print_connection_block(b);
}

void kn_remove_connection_block_from_list(struct connection_block *b)
{
    lck_mtx_lock(gConnectionBlockListLock);
    TAILQ_REMOVE(&connection_block_list, b, link);
    lck_mtx_unlock(gConnectionBlockListLock);
}

struct connection_block* kn_find_connection_block_with_address_in_list(u_int32_t saddr, u_int32_t daddr, u_int32_t sport, u_int32_t dport)
{
    struct connection_block *b = NULL, *tmp;
    boolean_t found = FALSE;
    
    if (gConnectionBlockListLock == NULL) 
        return NULL;
    
    lck_mtx_lock(gConnectionBlockListLock);
    TAILQ_FOREACH_REVERSE_SAFE(b, &connection_block_list, connection_block_list, link, tmp) {
        // currently source addresses don't match so ignore them for now
        //  && b->key.sport == sport && b->key.saddr == saddr
        
        if (b->key.daddr == daddr && b->key.dport == dport) {
            found = TRUE;
            break;
        }
    }
    lck_mtx_unlock(gConnectionBlockListLock);
    if (found) {
        kn_debug("found via address: ");
        kn_print_connection_block(b);
        return b;
    }
    else {
        return NULL;
    }
}

struct connection_block* kn_find_connection_block_with_socket_in_list(socket_t so)
{
    struct connection_block *b = NULL;
    boolean_t found = FALSE;
    
    if (gConnectionBlockListLock == NULL) 
        return NULL;
    
    lck_mtx_lock(gConnectionBlockListLock);
    TAILQ_FOREACH_REVERSE(b, &connection_block_list, connection_block_list, link) {
        if (b->socket == so) {
            found = TRUE;
            break;
        }
    }
    lck_mtx_unlock(gConnectionBlockListLock);
    if (found) {
        kn_debug("found via socket: ");
        kn_print_connection_block(b);
        return b;
    }
    else {
        kn_debug("failed connection block for socket 0x%X\n", so);
        return NULL;
    }
}

void kn_move_connection_block_to_tail(struct connection_block *b)
{
    lck_mtx_lock(gConnectionBlockListLock);
    TAILQ_REMOVE(&connection_block_list, b, link);
    TAILQ_INSERT_TAIL(&connection_block_list, b, link);
    lck_mtx_unlock(gConnectionBlockListLock);
}

void kn_reinject_all_deferred_packets_for_all()
{
    lck_mtx_lock(gConnectionBlockListLock);
    struct connection_block *b, *tmp;
    TAILQ_FOREACH_SAFE(b, &connection_block_list, link, tmp) {
        kn_cb_reinject_deferred_packets(b);
    }
    lck_mtx_unlock(gConnectionBlockListLock);
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
    
    struct deferred_packet *p, *tmp;
    
    TAILQ_FOREACH_SAFE(p, &b->deferred_packet_queue, link, tmp) {
        TAILQ_REMOVE(&b->deferred_packet_queue, p, link);
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
    int retval = 0;
    struct deferred_packet *p = (struct deferred_packet*)OSMalloc(sizeof(struct deferred_packet), gOSMallocTag);
    if (p == NULL) {
        kn_debug("OSMalloc returned error\n");
        return ENOMEM;
    }
    
    bzero(p, sizeof(struct deferred_packet));
    
    p->data = data;
    p->control = control;
    p->flags = flags;
    microtime(&p->timestamp);
    memcpy(&p->to, &to, sizeof(struct sockaddr_in));
    
    kn_mbuf_set_tag(&p->data, gidtag, kMY_TAG_TYPE, outgoing_direction);

    lck_mtx_lock(cb->lock);
    TAILQ_INSERT_TAIL(&cb->deferred_packet_queue, p, link);
    lck_mtx_unlock(cb->lock);
    
    kn_debug("kn_cb_add_deferred_packet: p 0x%X\n", p);

    return retval;
}

errno_t kn_cb_reinject_deferred_packets(struct connection_block* cb)
{
    struct deferred_packet *p, *tmp;
    int retval = 0, ret = 0;
    
    lck_mtx_lock(cb->lock);

    kn_debug("kn_cb_reinject_deferred_packets\n");
    
    TAILQ_FOREACH_REVERSE_SAFE(p, &cb->deferred_packet_queue, deferred_packet_head, link, tmp) {
        TAILQ_REMOVE(&cb->deferred_packet_queue, p, link);
        retval = kn_reinject_deferred_packet(cb->socket, p);
        if (retval != 0) {
            ret = retval;
            kn_debug("kn_reinject_deferred_packet returned error %d\n", retval);
        }
        else {
            
        }
        OSFree(p, sizeof(struct deferred_packet), gOSMallocTag);
    }
    lck_mtx_unlock(cb->lock);

    return ret;
}

connection_state kn_cb_state(struct connection_block* cb)
{
    connection_state ret;
    lck_mtx_lock(cb->lock);
    ret = cb->state;
    lck_mtx_unlock(cb->lock);
    return ret;
}

void kn_cb_set_state(struct connection_block* cb, connection_state state)
{
    lck_mtx_lock(cb->lock);
    cb->state = state;
    lck_mtx_unlock(cb->lock);
    return;
}


errno_t kn_reinject_deferred_packet(socket_t so, struct deferred_packet *p)
{
    kn_debug("kn_reinject_deferred_packet\n");
    int retval = 0;
    retval = sock_inject_data_out(so, NULL, p->data, p->control, p->flags);
    kn_debug("sock_inject_data_out returned %d\n", retval);
    if (retval != 0) {
        kn_debug("sock_inject_data_out returned error %d\n", retval);
    }
    return retval;
}

void kn_deferred_packet_watchdog_timer(void *param)
{
    struct connection_block *cb = NULL, *cb_tmp;
    struct deferred_packet *p = NULL, *p_tmp;
    struct timeval tv_now, tv_diff;
    long ms_diff;
    int retval = 0;
    int timeout; 
    
    timeout = kn_mr_RST_timeout_safe();
    
    kn_debug("kn_deferred_packet_watchdog_timer got called\n");
    
    microtime(&tv_now);
    
    lck_mtx_lock(gConnectionBlockListLock);
    TAILQ_FOREACH_SAFE(cb, &connection_block_list, link, cb_tmp) {
        lck_mtx_lock(cb->lock);
                
        TAILQ_FOREACH_SAFE(p, &cb->deferred_packet_queue, link, p_tmp) {
            kn_debug("kn_deferred_packet_watchdog_timer: p 0x%X\n", p);

            timersub(&tv_now, &p->timestamp, &tv_diff);
            ms_diff = tv_diff.tv_sec * 1000 + tv_diff.tv_usec / 1000;
            kn_debug("ms_diff: %d\n", ms_diff);

            if (ms_diff > timeout) {
                if (cb->state == injected_RST) {
                    cb->state = RST_timeout;
                }
                retval = kn_reinject_deferred_packet(cb->socket, p);
                if (retval != 0) {
                    kn_debug("kn_reinject_deferred_packet returned error %d\n", retval);
                }
                else {
                }
                TAILQ_REMOVE(&cb->deferred_packet_queue, p, link);
                OSFree(p, sizeof(struct deferred_packet), gOSMallocTag);
            }
        }
        lck_mtx_unlock(cb->lock);
    }
    lck_mtx_unlock(gConnectionBlockListLock);
    
    kn_debug("kn_deferred_packet_watchdog_timer returns\n");
    
    kn_register_deferred_packet_watchdog();
}

void kn_register_deferred_packet_watchdog()
{
    struct timespec ts;
    
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000 * kn_mr_RST_timeout_safe();
    
    bsd_timeout(kn_deferred_packet_watchdog_timer, NULL, &ts);
}

void kn_unregister_deferred_packet_watchdog()
{
    bsd_untimeout(kn_deferred_packet_watchdog_timer, NULL);
}

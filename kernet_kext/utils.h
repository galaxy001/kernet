//
//  utils.h
//  kernet
//
//  Created by Mike Chen on 9/17/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef UTILS_H
#define UTILS_H

// http://freebsd.active-venture.com/FreeBSD-srctree/newsrc/sys/ctype.h.html

#define isspace(c)	((c) == ' ' || ((c) >= '\t' && (c) <= '\r'))
#define isascii(c)	(((c) & ~0x7f) == 0)
#define isupper(c)	((c) >= 'A' && (c) <= 'Z')
#define islower(c)	((c) >= 'a' && (c) <= 'z')
#define isalpha(c)	(isupper(c) || islower(c))
#define isdigit(c)	((c) >= '0' && (c) <= '9')
#define isxdigit(c)	(isdigit(c) \
                    || ((c) >= 'A' && (c) <= 'F') \
                    || ((c) >= 'a' && (c) <= 'f'))

#define toupper(c)	((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))
#define tolower(c)	((c) + 0x20 * (((c) >= 'A') && ((c) <= 'Z')))

#define IN_RANGE(i, min, max) (i < min) || (i > max) ? 1 : 0
#define CAST_PTR_INT(X) (*((int*)(X)))

//char* kn_inet_ntoa_simple(u_int32_t ina);
//char* kn_inet_ntoa(u_int32_t ina, char* buf);
int kn_inet_aton(const char *cp, u_int32_t *addr);
void kn_debug(const char *fmt, ...);
void kn_msleep(u_int32_t milliseconds, char *channel, char *msg);

u_int16_t kn_tcp_sum_calc(u_int16_t len_tcp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[]);
u_int16_t kn_udp_sum_calc(u_int16_t len_udp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[]);


#endif

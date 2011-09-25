
#include <mach/mach_types.h>

#include "utils.h"
#include "common.h"
#include <sys/cdefs.h>
#include <kern/clock.h>

#include <sys/param.h>
#include <sys/systm.h>

#include <netinet/in.h>

/* As a matter of fact, I don't even bother to search for existing inet_ntoa in kernel space. I copied the following from freeBSD, I'm realy a bitch huh? */ 
char* kn_inet_ntoa_simple(u_int32_t ina) 
{
	static char buf[READABLE_IPv4_LENGTH];
	unsigned char *ucp = (unsigned char *)&ina;
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
	return buf;
}

char* kn_inet_ntoa(u_int32_t ina, char* buf) {
	unsigned char *ucp = (unsigned char *)&ina;
	snprintf(buf, READABLE_IPv4_LENGTH, "%d.%d.%d.%d", ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
    return buf;
}

void kn_msleep(u_int32_t milliseconds, char *channel, char *msg)
{
    struct timespec ts;    
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000 * milliseconds;

    msleep(channel, NULL, 0, msg, &ts);
}

/* It's stupid to look over how kernel handles checksuming. I'll implement my own. 
 * Following code is grabbed from http://www.bloof.de/tcp_checksumming
 *
 */

u_int16_t kn_tcp_sum_calc(u_int16_t len_tcp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[])
{
    u_char prot_tcp=6;
    u_int32_t sum;
    int nleft;
    u_int16_t *w;
	
    sum = 0;
    nleft = len_tcp;
    w=buff;
	
    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
	
    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
    {
    	/* sum += *w&0xFF; */
		sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
    }
	
    /* add the pseudo header */
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(prot_tcp);
	
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
	
    // Take the one's complement of sum
    sum = ~sum;
	
	return ((u_int16_t) sum);
}

u_int16_t kn_udp_sum_calc(u_int16_t len_udp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[])
{
    u_int32_t sum;
    int nleft;
    u_int16_t *w;
	
    sum = 0;
    nleft = len_udp;
    w=buff;
	
    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
	
    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
    {
    	/* sum += *w&0xFF; */
		sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
    }
	
    /* add the pseudo header */
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_udp);
    sum += htons(IPPROTO_UDP);
	
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
	
    // Take the one's complement of sum
    sum = ~sum;
	
	return ((u_int16_t) sum);
}

void kn_debug(const char *fmt, ...)
{
	va_list listp;
	char log_buffer[256];
	
	va_start(listp, fmt);
	
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, listp);
	printf("kernet: %s", log_buffer);
	
	va_end(listp);
}

int kn_inet_aton(const char *cp, u_int32_t *addr)
{
	u_int32_t parts[4];
	in_addr_t val;
	const char *c;
	char *endptr;
	int gotend, n;
    
	c = (const char *)cp;
	n = 0;
    
	/*
	 * Run through the string, grabbing numbers until
	 * the end of the string, or some error
	 */
	gotend = 0;
	while (!gotend) {
		u_int64_t l;
        
		l = strtoul(c, &endptr, 0);
        
		if (l == ULONG_MAX || (l == 0 && endptr == c))
			return (0);
        
		val = (in_addr_t)l;
        
		/*
		 * If the whole string is invalid, endptr will equal
		 * c.. this way we can make sure someone hasn't
		 * gone '.12' or something which would get past
		 * the next check.
		 */
		if (endptr == c)
			return (0);
		parts[n] = val;
		c = endptr;
        
		/* Check the next character past the previous number's end */
		switch (*c) {
            case '.' :
                
                /* Make sure we only do 3 dots .. */
                if (n == 3)	/* Whoops. Quit. */
                    return (0);
                n++;
                c++;
                break;
                
            case '\0':
                gotend = 1;
                break;
                
            default:
                if (isspace((unsigned char)*c)) {
                    gotend = 1;
                    break;
                } else {
                    
                    /* Invalid character, then fail. */
                    return (0);
                }
		}
        
	}
    
	/* Concoct the address according to the number of parts specified. */
	switch (n) {
        case 0:				/* a -- 32 bits */
            
            /*
             * Nothing is necessary here.  Overflow checking was
             * already done in strtoul().
             */
            break;
        case 1:				/* a.b -- 8.24 bits */
            if (val > 0xffffff || parts[0] > 0xff)
                return (0);
            val |= parts[0] << 24;
            break;
            
        case 2:				/* a.b.c -- 8.8.16 bits */
            if (val > 0xffff || parts[0] > 0xff || parts[1] > 0xff)
                return (0);
            val |= (parts[0] << 24) | (parts[1] << 16);
            break;
            
        case 3:				/* a.b.c.d -- 8.8.8.8 bits */
            if (val > 0xff || parts[0] > 0xff || parts[1] > 0xff ||
                parts[2] > 0xff)
                return (0);
            val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
            break;
	}
    
	if (addr != NULL)
		*addr = htonl(val);
	return (1);
}

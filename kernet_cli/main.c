#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "common.h"

static int gSocket = -1;
static u_int32_t req_seq;

void append_ip_range(const char* ip, int prefix, int port)
{
    struct in_addr addr;
    char buf[sizeof(struct request_t) + sizeof(struct append_ip_range_req_t)];
    struct request_t *req;
    struct append_ip_range_req_t *opt_req;

    req = (struct request_t*)buf;
    req->magic = CTL_MAGIC_WORD;
    req->id = req_seq;
    req_seq++;
    req->opt_code = CTL_OPT_APPEND_IP_RANGE;
    
    inet_aton(ip, &addr);
    
    opt_req = (struct append_ip_range_req_t*)(buf + sizeof(struct request_t));
    opt_req->ip = addr.s_addr;
    opt_req->netmask_bits = prefix;
    opt_req->policy = ip_range_kernet_2;
    opt_req->port = htons(port);
    
    if (send(gSocket, buf, sizeof(struct request_t) + sizeof(struct append_ip_range_req_t), 0) < 0) {
        perror("send");
    }
    else {
        printf("sent request, id %d, opt_code 0x%X\n", req->id, req->opt_code);
    }
}

void recv_print_response() {
    char buf[1024];
    int len;
    struct response_t *response;
    
    len = recv(gSocket, buf, 1024, 0);
    
    if (len > 0) {
        response = (struct response_t*)buf;
        printf("received response, id %d, opt_code 0x%X, ",response->id, response->opt_code);
        if (response->status == E_OKAY) {
            printf("okay\n");
        }
        else {
            printf("error %d\n", response->status);
        }
    }
    else if (len < 0) {
        perror("recv");
    }
}

int main (int argc, const char * argv[])
{
    struct sockaddr_ctl sc;
    struct ctl_info ctl_info;
    
    req_seq = 7936151;
    
    gSocket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (gSocket < 0) {
        perror("socket SYSPROTO_CONTROL");
		exit(0);
    }
    
    bzero(&ctl_info, sizeof(struct ctl_info));
	strcpy(ctl_info.ctl_name, KERNET_BUNDLEID);
	if (ioctl(gSocket, CTLIOCGINFO, &ctl_info) == -1) {
		perror("ioctl CTLIOCGINFO");
		exit(0);
	} else
		printf("ctl_id: 0x%x for ctl_name: %s\n", ctl_info.ctl_id, ctl_info.ctl_name);
    
    bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = SYSPROTO_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;
    
    if (connect(gSocket, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl))) {
		perror("connect");
		exit(0);
	}
    
    //append_ip_range("203.69.138.33", 32); /* akamai hinet node */
    append_ip_range("173.212.221.150", 32, 0);
    append_ip_range("4.3.2.0", 24, 0);
    append_ip_range("8.6.48.0", 21, 0);

    
    recv_print_response();
    
    close(gSocket);
    gSocket = -1;
    
    return 0;
}


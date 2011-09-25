//
//  KernetRequest.m
//  Kernet
//
//  Created by Mike Chen on 9/25/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import "KernetRequest.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

u_int32_t _next_identifier = 0;

@implementation KernetRequest
@synthesize data = _data;

+ (u_int32_t)nextIdentifier
{
    static NSLock *lock = NULL;
    u_int32_t ret = 0;
    
    if (lock == NULL) {
        lock = [[NSLock alloc] init];
    }
    
    [lock lock];
    ret = _next_identifier;
    _next_identifier++;
    [lock unlock];
    return ret;
}

- (id)initWithCode:(u_int8_t)code body:(NSData*)body
{
    self = [super init];
    if (self) {
        NSMutableData *d = [[NSMutableData alloc] initWithLength:sizeof(struct request_t)+[body length]];
        
        struct request_t *_request = (struct request_t*)[d mutableBytes];
        
        _request->magic = CTL_MAGIC_WORD;
        _request->opt_code = code;
        _request->id = [KernetRequest nextIdentifier];
        
        memcpy([d mutableBytes] + sizeof(struct request_t), [body bytes], [body length]);
        
        _data = [[NSData alloc] initWithData:d];
    }
    return self;
}

- (u_int32_t)identifier
{
    struct request_t *req = (struct request_t*)[_data bytes];
    return req->id;
}

+ (KernetRequest*)appendIPRangeRequestWithHostIP:(NSString*)ip bits:(int)bits port:(u_int32_t)port policy:(ip_range_policy)policy
{
    NSMutableData *data = [[[NSMutableData alloc] initWithCapacity:sizeof(struct append_ip_range_req_t)] autorelease];
    struct append_ip_range_req_t *req = (struct append_ip_range_req_t*)[data mutableBytes];
    
    if (inet_aton([ip cStringUsingEncoding:NSASCIIStringEncoding], (struct in_addr*)&req->ip) == 0) {
        NSLog(@"inet_aton returned error\n");
        return NULL;
    }
    
    req->port = htons(port);
    req->policy = policy;
    req->netmask_bits = bits;
    
    return [[[KernetRequest alloc] initWithCode:CTL_OPT_APPEND_IP_RANGE body:data] autorelease];
}

- (void)dealloc
{
    [_data release];
    [super dealloc];
}

@end

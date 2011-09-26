//
//  KernetInterface.m
//  Kernet
//
//  Created by Mike Chen on 9/25/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import "KernetInterface.h" 
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sys_domain.h>

#include "common.h"

static KernetInterface* __shared_kernet_interface = NULL;

static void socket_callback(CFSocketRef s,
                            CFSocketCallBackType callbackType,
                            CFDataRef address,
                            const void *data,
                            void *info
                            )
{
    KernetInterface *ki = (KernetInterface*)info;
}

@implementation KernetInterface
@synthesize delegate;
@synthesize requests;

+ (id)sharedInterface
{
    if (__shared_kernet_interface == NULL) {
        __shared_kernet_interface = [[KernetInterface alloc] init];
        __shared_kernet_interface.requests = [NSMutableArray arrayWithCapacity:10];
    }
    return __shared_kernet_interface;
}

- (NSData*)sysctlReadWithName:(NSString*)name length:(NSUInteger)len error:(NSError **)error
{
    int retval = 0;
    NSMutableData *buffer = [[[NSMutableData alloc] initWithLength:len] autorelease];
    
    size_t buflen = [buffer length];
    
    retval = sysctlbyname([name cStringUsingEncoding:NSASCIIStringEncoding], [buffer mutableBytes], &buflen, NULL, 0);
    
    if (retval != 0) {
        NSError *tmpError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        NSLog(@"Read %@ retuned error: %@", name, [tmpError localizedDescription]);
        if (error)
            *error = tmpError;
        return NULL;
    }
    else {
        if (error)
            *error = NULL;
        NSData *ret = [NSData dataWithBytes:[buffer bytes] length:buflen];
        return ret;
    }
}

- (NSError *)sysctlWriteWithName:(NSString*)name data:(NSData*)data
{
    NSError *error = NULL;
    int retval = 0;
    size_t len = [data length];
    
    if (geteuid() != 0) {
        NSLog(@"sysctl may fail for non-root users!\n\tIf it fails, try to run again with sudo.\n"); 
    }
        
    retval = sysctlbyname([name cStringUsingEncoding:NSASCIIStringEncoding], NULL, 0, (void*)[data bytes], len);
    
    if (retval != 0) {
        error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        NSLog(@"Write %@ retuned error: %@", name, [error localizedDescription]);
    }
    else {
        error = NULL;
    }
    return error;
}

- (KernetReturnValue)isPacketDelayEnabled
{
    NSError *error = NULL;
    NSString *sysctlName = @"net.kernet.packet_delay_enabled";
    KernetReturnValue ret = RV_UNKNOWN;
    
    NSData *data = [self sysctlReadWithName:sysctlName length:sizeof(int) error:&error];
    if (error == NULL) {
        int enabled = *(int*)([data bytes]);
        if (enabled == 1) 
            ret = RV_ENABLED;
        else if (enabled == 0) 
            ret = RV_DISABLED;
    }
    else {
        ret = RV_UNKNOWN;
    }
    return ret;
}

- (KernetReturnValue)isInjectionEnabled
{
    NSError *error = NULL;
    NSString *sysctlName = @"net.kernet.injection_enabled";
    KernetReturnValue ret = RV_UNKNOWN;
    
    NSData *data = [self sysctlReadWithName:sysctlName length:sizeof(int) error:&error];
    if (error == NULL) {
        int enabled = *(int*)([data bytes]);
        if (enabled == 1) 
            ret = RV_ENABLED;
        else if (enabled == 0) 
            ret = RV_DISABLED;
    }
    else {
        ret = RV_UNKNOWN;
    }
    return ret;
}

- (KernetReturnValue)isRSTDetectionEnabled
{
    NSError *error = NULL;
    NSString *sysctlName = @"net.kernet.RST_detection_enabled";
    KernetReturnValue ret = RV_UNKNOWN;
    
    NSData *data = [self sysctlReadWithName:sysctlName length:sizeof(int) error:&error];
    if (error == NULL) {
        int enabled = *(int*)([data bytes]);
        if (enabled == 1) 
            ret = RV_ENABLED;
        else if (enabled == 0) 
            ret = RV_DISABLED;
    }
    else {
        ret = RV_UNKNOWN;
    }
    return ret;
}

- (KernetReturnValue)isWatchdogEnabled
{
    NSError *error = NULL;
    NSString *sysctlName = @"net.kernet.watchdog_enabled";
    KernetReturnValue ret = RV_UNKNOWN;
    
    NSData *data = [self sysctlReadWithName:sysctlName length:sizeof(int) error:&error];
    if (error == NULL) {
        int enabled = *(int*)([data bytes]);
        if (enabled == 1) 
            ret = RV_ENABLED;
        else if (enabled == 0) 
            ret = RV_DISABLED;
    }
    else {
        ret = RV_UNKNOWN;
    }
    return ret;
}

- (KernetReturnValue)isFakeDNSResponseDroppingEnabled
{
    NSError *error = NULL;
    NSString *sysctlName = @"net.kernet.fake_DNS_response_dropping_enabled";
    KernetReturnValue ret = RV_UNKNOWN;
    
    NSData *data = [self sysctlReadWithName:sysctlName length:sizeof(int) error:&error];
    if (error == NULL) {
        int enabled = *(int*)([data bytes]);
        if (enabled == 1) 
            ret = RV_ENABLED;
        else if (enabled == 0) 
            ret = RV_DISABLED;
    }
    else {
        ret = RV_UNKNOWN;
    }
    return ret;
}

- (NSInteger)RSTTimeout
{
    NSError *error = NULL;
    NSString *sysctlName = @"net.kernet.RST_timeout";
    NSInteger ret = -1;
    
    NSData *data = [self sysctlReadWithName:sysctlName length:sizeof(int) error:&error];
    if (error == NULL) {
        int timeout = *(int*)([data bytes]);
        ret = timeout;
    }
    else {
        ret = -1;
    }
    return ret;
}

- (NSError *)setPacketDelayEnabled:(BOOL)enabled
{
    NSError *error = NULL;
    static NSString *sysctlName = @"net.kernet.packet_delay_enabled";

    int value = (enabled ? 1 : 0);
    
    error = [self sysctlWriteWithName:sysctlName data:[NSData dataWithBytes:&value length:sizeof(value)]];
    return error;
}

- (NSError *)setInjectionEnabled:(BOOL)enabled
{
    NSError *error = NULL;
    static NSString *sysctlName = @"net.kernet.injection_enabled";
    
    int value = (enabled ? 1 : 0);
    
    error = [self sysctlWriteWithName:sysctlName data:[NSData dataWithBytes:&value length:sizeof(value)]];
    return error;
}

- (NSError *)setRSTDetectionEnabled:(BOOL)enabled
{
    NSError *error = NULL;
    static NSString *sysctlName = @"net.kernet.RST_detection_enabled";
    
    int value = (enabled ? 1 : 0);
    
    error = [self sysctlWriteWithName:sysctlName data:[NSData dataWithBytes:&value length:sizeof(value)]];
    return error;
}

- (NSError *)setWatchdogEnabled:(BOOL)enabled
{
    NSError *error = NULL;
    static NSString *sysctlName = @"net.kernet.watchdog_enabled";
    
    int value = (enabled ? 1 : 0);
    
    error = [self sysctlWriteWithName:sysctlName data:[NSData dataWithBytes:&value length:sizeof(value)]];
    return error;
}

- (NSError *)setFakeDNSResponseDroppingEnabled:(BOOL)enabled
{
    NSError *error = NULL;
    static NSString *sysctlName = @"net.kernet.fake_dns_response_dropping_enabled";
    
    int value = (enabled ? 1 : 0);
    
    error = [self sysctlWriteWithName:sysctlName data:[NSData dataWithBytes:&value length:sizeof(value)]];
    return error;
}

- (NSError *)setRSTTimeout:(NSUInteger)timeout
{
    NSError *error = NULL;
    static NSString *sysctlName = @"net.kernet.RST_timeout";
    
    int value = (int)timeout;
    
    error = [self sysctlWriteWithName:sysctlName data:[NSData dataWithBytes:&value length:sizeof(value)]];
    return error;
}

- (void)connectToKext
{
    NSError *error = NULL;
    CFMutableDataRef addr = NULL;
    CFRunLoopSourceRef runloop = NULL;
    
    const CFSocketContext context ={ 0, self, NULL, NULL, NULL };
    
    socket = CFSocketCreate(kCFAllocatorDefault, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL, kCFSocketReadCallBack | kCFSocketConnectCallBack, socket_callback, &context);
    if (socket == NULL) {
        error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        NSLog(@"socket() returned error: %@", [error localizedDescription]);
        [self.delegate performSelector:@selector(connectionToKextFailedWithError:) withObject:error afterDelay:0.0f];
        return;
    }
    
    bzero(&ctl_info, sizeof(struct ctl_info));
	strcpy(ctl_info.ctl_name, KERNET_BUNDLEID);
	if (ioctl(CFSocketGetNative(socket), CTLIOCGINFO, &ctl_info) == -1) {
        error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        NSLog(@"ioctl(CTLIOCGINFO) returned error: %@", [error localizedDescription]);
        [self.delegate performSelector:@selector(connectionToKextFailedWithError:) withObject:error afterDelay:0.0f];
        goto CLEAN;
	} else
		NSLog(@"ctl_id: 0x%x for ctl_name: %s\n", ctl_info.ctl_id, ctl_info.ctl_name);
    
    addr = CFDataCreateMutable(kCFAllocatorDefault, sizeof(struct sockaddr_ctl));
    struct sockaddr_ctl *sc = (struct sockaddr_ctl*)CFDataGetMutableBytePtr(addr);
    bzero(sc, sizeof(struct sockaddr_ctl));
	sc->sc_len = sizeof(struct sockaddr_ctl);
	sc->sc_family = AF_SYSTEM;
	sc->ss_sysaddr = SYSPROTO_CONTROL;
	sc->sc_id = ctl_info.ctl_id;
	sc->sc_unit = 0;
    
    if (connect(CFSocketGetNative(socket), (struct sockaddr*)sc, sizeof(struct sockaddr_ctl)) != 0) {
        error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        NSLog(@"connect() returned error: %@", [error localizedDescription]);
        [self.delegate performSelector:@selector(connectionToKextFailedWithError:) withObject:error afterDelay:0.0f];
        goto CLEAN;
    }
    else {
        [self.delegate performSelector:@selector(connectionToKextSucceeded) withObject:nil afterDelay:0.0f];
    }
    CFRelease(addr);
    addr = NULL;
    
    runloop = CFSocketCreateRunLoopSource(NULL, socket, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), runloop, kCFRunLoopDefaultMode);
    CFRelease(runloop);
    runloop = NULL;
    
    return; 
    
CLEAN:
    CFRelease(socket);
    socket = NULL;
    if (runloop)
        CFRelease(runloop);
    if (addr)
        CFRelease(addr);
    return;
}

- (void)disconnect
{
    CFSocketInvalidate(socket);
    CFRelease(socket);
    [self.requests removeAllObjects];
}

- (void)sendRequest:(KernetRequest*)request
{
    size_t ret = 0;
    socklen_t len = [[request data] length];
    ret = send(CFSocketGetNative(socket), [[request data] bytes], len, 0);
    if (ret != len) {
        [self.delegate performSelector:@selector(sendRequestFailed:) withObject:request afterDelay:0.0f];
    }
    else {
        [self.requests addObject:request];
        [self.delegate performSelector:@selector(sentRequest:) withObject:request afterDelay:0.0f];
    }
}

@end

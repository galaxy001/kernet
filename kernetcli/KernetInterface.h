//
//  KernetInterface.h
//  Kernet
//
//  Created by Mike Chen on 9/25/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <sys/kern_control.h>
#include "KernetRequest.h"

typedef enum _KernetReturnValue {
    RV_ENABLED = 1,
    RV_DISABLED, 
    RV_UNKNOWN,
} KernetReturnValue;

@protocol KernetInterfaceDelegate <NSObject>
@required
- (void)performSelector:(SEL)aSelector withObject:(id)anArgument afterDelay:(NSTimeInterval)delay;

- (void)connectionToKextFailedWithError:(NSError*)error;
- (void)connectionToKextSucceeded;
- (void)sentRequest:(KernetRequest*)req;
- (void)sendRequestFailed:(KernetRequest*)req;

@end

@interface KernetInterface : NSObject
{
    struct ctl_info ctl_info;
    CFSocketRef socket;
    
    id<KernetInterfaceDelegate> delegate;
    
    NSMutableArray *requests;
}
@property (assign) id<KernetInterfaceDelegate> delegate;
@property (retain) NSMutableArray *requests;

+ (id)sharedInterface;

- (void)connectToKext;
- (void)disconnect;
- (void)sendRequest:(KernetRequest*)request;

- (NSData*)sysctlReadWithName:(NSString*)name length:(NSUInteger)len error:(NSError **)error;
- (KernetReturnValue)isPacketDelayEnabled;
- (KernetReturnValue)isInjectionEnabled;
- (KernetReturnValue)isRSTDetectionEnabled;
- (KernetReturnValue)isWatchdogEnabled;
- (KernetReturnValue)isFakeDNSResponseDroppingEnabled;
- (NSInteger)RSTTimeout;

- (NSError *)sysctlWriteWithName:(NSString*)name data:(NSData*)data;
- (NSError *)setPacketDelayEnabled:(BOOL)enabled;
- (NSError *)setInjectionEnabled:(BOOL)enabled;
- (NSError *)setRSTDetectionEnabled:(BOOL)enabled;
- (NSError *)setWatchdogEnabled:(BOOL)enabled;
- (NSError *)setFakeDNSResponseDroppingEnabled:(BOOL)enabled;
- (NSError *)setRSTTimeout:(NSUInteger)timeout;



@end

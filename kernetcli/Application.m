//
//  Application.m
//  Kernet
//
//  Created by Mike Chen on 9/25/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import "Application.h"

@implementation Application

- (id)init
{
    self = [super init];
    if (self) {
        // Initialization code here.
    }
    
    return self;
}

- (void)main:(id)sender
{
    [[KernetInterface sharedInterface] setDelegate:self];
    [[KernetInterface sharedInterface] connectToKext];
}

- (void)connectionToKextSucceeded
{
    KernetRequest *req = [KernetRequest appendIPRangeRequestWithHostIP:@"173.212.221.150" bits:32 port:80 policy:ip_range_direct];
    [[KernetInterface sharedInterface] sendRequest:req];
}

- (void)connectionToKextFailedWithError:(NSError *)error
{
    
}

- (void)sentRequest:(KernetRequest *)req
{
    
}

- (void)sendRequestFailed:(KernetRequest *)req
{
    
}

@end

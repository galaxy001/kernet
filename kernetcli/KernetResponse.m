//
//  KernetResponse.m
//  Kernet
//
//  Created by Mike Chen on 9/25/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import "KernetResponse.h"

@implementation KernetResponse

- (id)initWithData:(NSData*)d;
{
    self = [super init];
    if (self) {
        data = [d retain];
    }
    
    return self;
}

- (struct response_t*)responseHeader
{
    return (struct response_t*)[data bytes];
}

- (void)dealloc
{
    [data release];
    [super dealloc];
}

@end

//
//  KernetResponse.h
//  Kernet
//
//  Created by Mike Chen on 9/25/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "common.h"

@interface KernetResponse : NSObject
{
    NSData *data;
}
- (id)initWithData:(NSData*)d;
- (struct response_t*)responseHeader;

@end

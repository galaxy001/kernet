//
//  KernetRequest.h
//  Kernet
//
//  Created by Mike Chen on 9/25/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "common.h"

@interface KernetRequest : NSObject
{
    NSData *_data;
}
@property (readonly) NSData *data;
- (id)initWithCode:(u_int8_t)code body:(NSData*)body;
- (u_int32_t)identifier;
+ (u_int32_t)nextIdentifier;

+ (KernetRequest*)appendIPRangeRequestWithHostIP:(NSString*)ip bits:(int)bits port:(u_int32_t)port policy:(ip_range_policy)policy;

@end

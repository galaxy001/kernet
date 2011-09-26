//
//  main.m
//  kernetcli
//
//  Created by Mike Chen on 9/25/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Application.h"
#import "common.h"

int main (int argc, const char * argv[])
{
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
    
    Application *app = [[Application alloc] init];
    
    NSTimer *timer = [[NSTimer alloc] initWithFireDate:[NSDate date] interval:0.0f target:app selector:@selector(main:) userInfo:nil repeats:NO];
    
    NSRunLoop *runloop = [NSRunLoop mainRunLoop];
    [runloop addTimer:timer forMode:NSRunLoopCommonModes];
    [timer release];
    [runloop run];
    [pool drain];
    return 0;
}


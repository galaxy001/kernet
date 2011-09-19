//
//  sysctl.h
//  kernet
//
//  Created by Mike Chen on 9/19/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef SYSCTL_H
#define SYSCTL_H

#define CAST_PTR_INT(X) (*((int*)(X)))

errno_t kn_register_sysctls();
errno_t kn_unregister_sysctls();

#endif

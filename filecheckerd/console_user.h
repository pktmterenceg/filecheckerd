//
//  console_user.h
//  filecheckerd
//
//  Created by Terence Goggin on 06/16/14.
//  Copyright (c) 2014 Terence Goggin. All rights reserved.
//

#ifndef filecheckerd_console_user_h
#define filecheckerd_console_user_h

#import <Foundation/Foundation.h>

//Currently-logged-in user stuff
#include <SystemConfiguration/SystemConfiguration.h>

#define kErrMsg_CantGetLoggedOnUser @"Unable to determine currently logged-on console user."
NSString * currentlyLoggedOnUser();

#endif
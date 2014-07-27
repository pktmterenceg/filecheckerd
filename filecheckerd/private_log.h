//
//  private_log.h
//  filecheckerd
//
//  Created by Terence Goggin on 06/16/14.
//  Copyright (c) 2014 Terence Goggin. All rights reserved.
//


#ifndef filecheckerd_private_log
#define filecheckerd_private_log

#import <Foundation/Foundation.h>
//#import <dispatch/dispatch.h>
#include <stdio.h>

#define kLogFilePath @"/private/var/log/filecheckerd-likely-malware.log"
#define kErrMsg_CantOpenLog @"Can't open log for writing."

void PrivateLog (NSString *format, ...);
void initPrivateLog();
void releasePrivateLog();

#endif
//
//  private_log.m
//  filecheckerd
//
//  Created by Terence Goggin on 06/16/14.
//  Copyright (c) 2014 Terence Goggin. All rights reserved.
//

#import "private_log.h"
#include <stdio.h>

//Yes, that's a global variable. Yes, I know.
static FILE *privatelog = 0;

void PrivateLog (NSString *format, ...) {
    
    if (format == nil) {
        //printf("nil\n");
        return;
    }
    va_list argList;
    va_start(argList, format);
    
    NSMutableString *s = [[NSMutableString alloc] initWithFormat:format
                                                       arguments:argList];
    NSLog(@"%@", s); //also NSLog it. Because paranoia.
    [s insertString: [NSString stringWithFormat: @"%@ : ", [[NSDate date] description] ] atIndex: 0];
    [s appendString: @"\n"];
    
    fprintf(privatelog, "%s", (const char*) [s UTF8String]);
    [s release];
    va_end(argList);
    return ;
}

void initPrivateLog(){
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (privatelog == 0) {
            privatelog = fopen([kLogFilePath UTF8String], "wt"); //changed to "wt" to keep log size reasonable
            if (!privatelog) privatelog = fopen([kLogFilePath UTF8String], "wt");
            if (!privatelog) {
                NSLog(kErrMsg_CantOpenLog);
                return;   // bail out if we can't log
            }
        }
    });    
}

void releasePrivateLog(){
    if (privatelog)
        fclose(privatelog);
}
//
//  console_user.m
//  filecheckerd
//
//  Created by Terence Goggin on 06/16/14.
//  Copyright (c) 2014 Terence Goggin. All rights reserved.
//

#import "console_user.h"


//From http://superuser.com/questions/180819/how-can-you-find-out-the-currently-logged-in-user-in-the-os-x-gui
// which in turn was from QA1133: http://developer.apple.com/mac/library/qa/qa2001/qa1133.html
//
//TG: Yes, I realize the result is potentially unknown in the case of fast user switching, but I'm honestly not sure how to handle this.
//  However, as my father used to say, you can't beat something with nothing.
//  Suggestions? Please?

NSString * currentlyLoggedOnUser(){
    SCDynamicStoreRef store;
    CFStringRef name;
    uid_t uid;
    
    NSString *result = [NSString string];
    
    store = SCDynamicStoreCreate(NULL, CFSTR("GetConsoleUser"), NULL, NULL);

    if (store == NULL){
        NSLog(kErrMsg_CantGetLoggedOnUser);
        return result;
    }
    name = SCDynamicStoreCopyConsoleUser(store, &uid, NULL);
    CFRelease(store);
    
    if (name != NULL) {
        result = [NSString stringWithString: (NSString *) name];
        CFRelease(name);
    }
    
    return result;
}
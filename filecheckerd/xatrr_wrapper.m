//
//  xatrr_wrapper.c
//  filecheckerd
//
//  Created by Terence Goggin on 06/16/14.
//  Copyright (c) 2014 Terence Goggin. All rights reserved.
//



#include "xatrr_wrapper.h"

//Adapted from: http://www.cocoanetics.com/2012/03/reading-and-writing-extended-file-attributes/
//TG: I'm still playing with the idea of tacking on an attribute to a file that I have already hashed as a further means
//  of marking it as already known to be bad. As of yet, though, this remains unused. 

NSString *getExtendedAttribute(NSString *filePath, NSString *attributeName){
    
    // get size of needed buffer
    long bufferLength = getxattr([filePath UTF8String], [attributeName UTF8String], NULL, 0, 0, 0);
    
    // make a buffer of sufficient length
    char *buffer = malloc(bufferLength);
    
    // now actually get the attribute string
    getxattr([filePath UTF8String], [attributeName UTF8String], buffer, bufferLength, 0, 0);
    
    // convert to NSString
    NSString *retString = [NSString stringWithUTF8String: buffer];
    
    // release buffer
    free(buffer);
    return retString;
}

int setExtendedAttribute(NSString *filePath, NSString *attributeName, NSString *attributeValue){

    int result = setxattr([filePath UTF8String], [attributeName UTF8String], [attributeValue UTF8String], strlen([attributeValue UTF8String]), 0, 0);
    return result;
}


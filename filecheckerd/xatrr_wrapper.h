//
//  xatrr_wrapper.h
//  filecheckerd
//
//  Created by Terence Goggin on 06/16/14.
//  Copyright (c) 2014 Terence Goggin. All rights reserved.
//

#ifndef filecheckerd_xatrr_wrapper_h
#define filecheckerd_xatrr_wrapper_h

#include <stdio.h>
#include <Foundation/Foundation.h>
#include <sys/xattr.h>

NSString *getExtendedAttribute(NSString *filePath, NSString *attributeName);
int setExtendedAttribute(NSString *filePath, NSString *attributeName, NSString *attributeValue);


#endif

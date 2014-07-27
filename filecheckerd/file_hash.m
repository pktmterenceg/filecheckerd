//
//  file_hash.m
//  filecheckerd
//
//  Created by Terence Goggin on 06/16/14.
//  Copyright (c) 2014 Terence Goggin. All rights reserved.
//

#import "file_hash.h"

@implementation NSArray (fileExtensions)
    + (NSArray *)suspiciousFileExtensions
    {
        static NSArray *_exts;
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            _exts = [NSArray arrayWithObjects:
                                            @"rar",
                                            @"com",
                                            @"exe",
                                            @"scr",
                                            @"pif",
                                            @"bat",
                                            @"cmd",
                                            @"vb",
                                            @"ws",
                                            @"hta",
                                            @"sys",
                                            //other reasonable precautions
                                            @"flv",
                                            @"pdf",
                                            @"dll",
                                            @"scr",
                                            @"ocx",
                                            @"cpl",
                                            @"fon",
                                            @"lnk",
                                            @"msi",
                                            @"msp",
                                            @"sh",
                                            @"torrent",
                                            @"csh",
                                            @"pl",
                                            @"py",
                                            @"jar",
                                            @"tar",
                                            @"gz",
                                            @"zip" , nil];
            
        });
        return _exts;
    }
@end
/*
 //http://stackoverflow.com/questions/3469218/cocoa-detect-unmountable-volume
 BOOL isRemovable, isWritable, isUnmountable;
 NSString *description, *type;
 
 BOOL succ = [[NSWorkspace sharedWorkspace] getFileSystemInfoForPath:[itemInfo objectForKey:@"path"]
 isRemovable:&isRemovable
 isWritable:&isWritable
 isUnmountable:&isUnmountable
 description:&description
 type:&type];
 */

BOOL quarantineFile(NSString *fileToQuarantine){
    @autoreleasepool {
        NSFileManager *fileManager = [[[NSFileManager alloc] init] autorelease];
        NSString *consoleUser = currentlyLoggedOnUser();

        NSError *error = nil;
        if ([consoleUser length]){
            NSString *newPath = [NSString stringWithFormat: kQuarantineFolderPathFormatString,
                                 consoleUser, kRenameString, [fileToQuarantine lastPathComponent]];
            if (![fileManager moveItemAtPath:fileToQuarantine toPath: newPath error: &error]){
                PrivateLog(kErrMsg_CantQuarantine, fileToQuarantine);
                PrivateLog(kErrMsg_GenericError, error, fileToQuarantine);
                return renameFileInPlace(fileToQuarantine);
            }
            else {
                return YES;
            }
        }
        else { //couldn't get console user
            //TG: So, now what? I'm going with "rename in place" for the time being.
            return renameFileInPlace(fileToQuarantine);
        }
    }
}

//TG: failover for when file can't be moved. 
BOOL renameFileInPlace(NSString *fileToQuarantine){
    @autoreleasepool {
        NSFileManager *fileManager = [[[NSFileManager alloc] init] autorelease];

        NSString *newPath = [NSString stringWithFormat: @"%@%@%@",
                             [fileToQuarantine stringByDeletingLastPathComponent], kRenameString, [fileToQuarantine lastPathComponent]];
        NSError *error = nil;
        if (![fileManager moveItemAtPath:fileToQuarantine toPath: newPath error: &error]){
            PrivateLog(kErrMsg_CantQuarantine, fileToQuarantine);
            PrivateLog(kErrMsg_GenericError, error, fileToQuarantine);
            return NO;
        }
        else {
            return YES;
        }
    }
}

void doHash(NSString *fileToCheck){
    @autoreleasepool {
        if ([fileToCheck isEqualToString: kLogFilePath]){
            return ; //TG: don't hash your own log file. You'll be here all day. Not perfect, no. 
        }
        //http://nshipster.com/nsrange/
        if ([fileToCheck rangeOfString: kRenameString].location != NSNotFound){
            //TG: I already hashed & quarantined it. No, it's not perfect, but there must be some way to avoid re-hasing old stuff. See what I did there?
            return ;
        }
        NSData *contents = [NSData dataWithContentsOfFile: fileToCheck];
        unsigned int outputLength = CC_SHA1_DIGEST_LENGTH;
        unsigned char output[outputLength];
        
        if (![contents length]){
            PrivateLog(kErrMsg_ZeroBytes, fileToCheck);
            return ;
        }
        
        CC_SHA1([contents bytes], (unsigned int) [contents length], output);
        NSData *hashData = [NSMutableData dataWithBytes:output length:outputLength];
        NSUInteger dataLength = [hashData length];
        NSMutableString *hashString = [NSMutableString stringWithCapacity:dataLength*2];
        const unsigned char *dataBytes = [hashData bytes];
        for (NSInteger idx = 0; idx < dataLength; ++idx) {
            [hashString appendFormat:@"%02x", dataBytes[idx]];
        }
        
        //TG: Seriously, if you like this even a little bit, please consider donating to the good folk at Team Cymru, who provide the backend hash data/services:
        //  http://www.team-cymru.org/About/friendsof.html
        NSHost *malware = [NSHost hostWithName: [hashString stringByAppendingString: kCymruDNSSuffix]];

        if ([[malware address] isEqualToString: kHashMatchFoundIP]){
            //TG: EXTERMINATE! EXTERMINATE!
            PrivateLog(kErrMsg_MatchFound, fileToCheck);
            PrivateLog(kErrMsg_ActualHash, hashString);
            //quarantine and rename
            quarantineFile(fileToCheck);      
            
        }
    }
}



//TG: dir iterating code from:
//  http://stackoverflow.com/questions/5749488/iterating-through-files-in-a-folder-with-nested-folders-cocoa
void directoryDoHash(NSString *dirPath){
    @autoreleasepool {
        struct statfs fileStat;
        statfs([dirPath UTF8String], &fileStat);
        if (fileStat.f_flags & MNT_RDONLY){
            PrivateLog(kErrMsg_ReadOnlyMedia, dirPath);
            //return ;
        }
        NSFileManager *fileManager = [[[NSFileManager alloc] init] autorelease];
        NSURL *directoryURL = [[NSURL alloc] initFileURLWithPath: dirPath];// URL pointing to the directory you want to browse
        NSArray *keys = [NSArray arrayWithObject:NSURLIsDirectoryKey];
        
        NSDirectoryEnumerator *enumerator = [fileManager
                                             enumeratorAtURL:directoryURL
                                             includingPropertiesForKeys:keys
                                             options:0
                                             errorHandler:^(NSURL *url, NSError *error) {
                                                 //TG: Handle the error.
                                                 // Return YES if the enumeration should continue after the error.
                                                 return YES;
                                             }];
        
        for (NSURL *url in enumerator) {
            NSError *error;
            NSNumber *isDirectory = nil;
            if (! [url getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&error]) {
                //TG: handle error
                //Log? Warn? Both? Punt, apparently.
            }
            else if (! [isDirectory boolValue]) {
                //TG: No error and it’s not a directory; do something with the file
                doHash([url path]);
            }
            else if ( [isDirectory boolValue]){
                //TG: if it's a directory, repeat the process
                directoryDoHash([url path]);
            }
        }
    }
    
}
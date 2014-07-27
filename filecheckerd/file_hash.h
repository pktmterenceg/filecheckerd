//
//  file_hash.h
//  filecheckerd
//
//  Created by Terence Goggin on 06/16/14.
//  Copyright (c) 2014 Terence Goggin. All rights reserved.
//

#ifndef filecheckerd_file_hash_h
#define filecheckerd_file_hash_h

#import <Foundation/Foundation.h>
#include "private_log.h"
#include "xatrr_wrapper.h"
#include "console_user.h"
#include <sys/param.h>
#include <sys/mount.h>

//hashing stuff
#import <CommonCrypto/CommonDigest.h>
#define kHashMatchFoundIP @"127.0.0.2"
#define kCymruDNSSuffix @".malware.hash.cymru.com"

#define kErrMsg_CouldntStat     @"Warning: Couldn't stat file %@; File moved or deleted before it could be hashed."
#define kErrMsg_ZeroBytes       @"Warning: File %@ empty or possibly deleted before it could be hashed."
#define kErrMsg_MatchFound      @"MATCH FOUND: File matches known malware samples: %@."
#define kErrMsg_ActualHash      @"MATCH FOUND: Hash that gave a match: %@"
#define kErrMsg_MatchMoved      @"MATCH FOUND: Matching file (%@) moved to trash and renamed."
#define kErrMsg_CantQuarantine  @"MATCH NOT QUARANTINED: Couldn't move file %@ to trash."
#define kErrMsg_RenamedInPlace  @"MATCH RENAMED IN PLACE: %@ is now %@."
#define kErrMsg_CantRename      @"MATCH NOT RENAMED: %@"
#define kErrMsg_ReadOnlyMedia   @"READ-ONLY MEDIA: %@; matches found will not be quarantined."
#define kErrMsg_GenericError    @"[Error] %@ (%@)"


#define kRenameString       @"LikelyMalware-DoNotOpen."


//Quarantine paths
NSString *quarantinePath;
#define kQuarantineFolderPathFormatString @"/Users/%@/.Trash/%@%@"

@interface NSArray (fileExtensions)
+ (NSArray *)suspiciousFileExtensions;
@end

BOOL quarantineFile(NSString *fileToQuarantine);
BOOL renameFileInPlace(NSString *fileToQuarantine);

void doHash(NSString *fileToCheck);
void directoryDoHash(NSString *dirPath);


#endif

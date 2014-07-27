//
//  main.m
//  filecheckerd
//
//  Created by Terence Goggin on 05/26/14.
//  Copyright (c) 2014 Terence Goggin.
//
//  As per the rules of such things, this code is based largely on Amit Singh's excellent work, and is therefore
//  licensed under the same terms. To wit:
//  
//  Source released under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.0.
//  See http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt for details.
//

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
//TG: Oh, yeah: you're gonna have to download the xnu source and install it
// For this, see: http://shantonu.blogspot.de/2012/07/building-xnu-for-os-x-108-mountain-lion.html
//            or: http://shantonu.blogspot.de/2013/10/building-xnu-for-os-x-109-mavericks.html


// for ioctl(2)
#include <sys/ioctl.h>
#include <sys/sysctl.h>

// for read(2)
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// for printf(3)
#include <stdio.h>

// for exit(3)
#include <stdlib.h>

// for strncpy(3)
#include <string.h>

// for getpwuid(3)
#include <pwd.h>

// for getgrgid(3)
#include <grp.h>

// for S_IS*(3)
#include <sys/stat.h>

//for sys max values, like max path len
#include <sys/syslimits.h>
#include <sys/fsevents.h>
//TG: Counter-intuitively, mounting a volume does not count as an fsevent, even though it obviously creates an entry under /Volumes.
//  Hence, the inclusion of DiskArbitration.
#include <DiskArbitration/DiskArbitration.h>

#include "private_log.h"
#include "xatrr_wrapper.h"
#include "console_user.h"
#include "file_hash.h"


#define MODE_STRING_LENGTH 10

#define PROGNAME "filecheckerd"
#define PROGVERS "1.2"

#define DEV_FSEVENTS     "/dev/fsevents" // the fsevents pseudo-device
#define FSEVENT_BUFSIZ   131072          // buffer for reading from the device
#define EVENT_QUEUE_SIZE 4096            // limited by MAX_KFS_EVENTS
#define kDADiskDescriptionAppearanceTimeKey @"DAAppearanceTime" //Not sure why this isn't defined by DiskArbitration
#define kRecentlyMountedTimeWindowSeconds 30
//TG: TODO: filechekerd preferences
#define kPrefsFilePath @"/Library/Preferences/in.gogg.filecheckerd" 


void diskAppearedHandler(DADiskRef disk, void *context);

//TG: DiskArbitration framework initially provides information about disks already mounted, as opposed to those mounted during the run of the program.
//  This not what I'd expect from the descriptions of the methods, constant names, etc. Odd.
//  So, to work around this, I check to see if the disk was recently mounted, and then branch on that.
void diskAppearedHandler(DADiskRef disk, void *context){
    CFDictionaryRef *diskinfo;
    diskinfo = (CFDictionaryRef *)DADiskCopyDescription(disk);
    id value = CFDictionaryGetValue(diskinfo, kDADiskDescriptionAppearanceTimeKey);
    NSDate *dateMounted = [NSDate dateWithTimeIntervalSinceReferenceDate:[value doubleValue]];
    NSDate *lastMinute = [NSDate dateWithTimeInterval:-kRecentlyMountedTimeWindowSeconds sinceDate: [NSDate date]];
    //check to see if this is a newly mounted item
    if (([dateMounted compare:lastMinute] != NSOrderedAscending) && ([dateMounted compare: [NSDate date]] != NSOrderedDescending)){
        NSString *path = [((NSURL *)CFDictionaryGetValue(diskinfo, kDADiskDescriptionVolumePathKey)) path];
        directoryDoHash(path);
    }
    CFRelease(diskinfo);
}




// converts mode number to ls-style mode string
static void get_mode_string(int32_t mode, char *buf) {
    buf[10] = '\0';
    buf[9] = mode & 0x01 ? 'x' : '-';
    buf[8] = mode & 0x02 ? 'w' : '-';
    buf[7] = mode & 0x04 ? 'r' : '-';
    buf[6] = mode & 0x08 ? 'x' : '-';
    buf[5] = mode & 0x10 ? 'w' : '-';
    buf[4] = mode & 0x20 ? 'r' : '-';
    buf[3] = mode & 0x40 ? 'x' : '-';
    buf[2] = mode & 0x80 ? 'w' : '-';
    buf[1] = mode & 0x100 ? 'r' : '-';
    
    // ls style mode string
    if (S_ISFIFO(mode)) {
        buf[0] = 'p';
    } else if (S_ISCHR(mode)) {
        buf[0] = 'c';
    } else if (S_ISDIR(mode)) {
        buf[0] = 'd';
    } else if (S_ISBLK(mode)) {
        buf[0] = 'b';
    } else if (S_ISLNK(mode)) {
        buf[0] = 'l';
    } else if (S_ISSOCK(mode)) {
        buf[0] = 's';
    } else {
        buf[0] = '-';
    }
}


int hasForbiddenExtension(NSString *filename){
    //TG: TODO: read list of forbidden extensions from file/preference
    //  For now, borrow list from here:  https://wiki.csuchico.edu/confluence/display/help/Blocked+E-mail+Attachments+File+Types
    //  and add .torrent, .jar, and a few *nix-related extensions to be "safe"
    NSArray *exts = [NSArray suspiciousFileExtensions];
    NSString *file = [filename lastPathComponent];
    BOOL bresult = ([exts indexOfObjectIdenticalTo: file] != NSNotFound) ;
    return bresult;
    
}



// an event argument
typedef struct kfs_event_arg {
    u_int16_t  type;         // argument type
    u_int16_t  len;          // size of argument data that follows this field
    union {
        struct vnode *vp;
        char         *str;
        void         *ptr;
        int32_t       int32;
        dev_t         dev;
        ino_t         ino;
        int32_t       mode;
        uid_t         uid;
        gid_t         gid;
        uint64_t      timestamp;
    } data;
} kfs_event_arg_t;

#define KFS_NUM_ARGS  FSE_MAX_ARGS

// an event
typedef struct kfs_event {
    int32_t         type; // event type
    pid_t           pid;  // pid of the process that performed the operation
    kfs_event_arg_t args[KFS_NUM_ARGS]; // event arguments
} kfs_event;

// event names
/*static const char *kfseNames[] = {
    "FSE_CREATE_FILE",
    "FSE_DELETE",
    "FSE_STAT_CHANGED",
    "FSE_RENAME",
    "FSE_CONTENT_MODIFIED",
    "FSE_EXCHANGE",
    "FSE_FINDER_INFO_CHANGED",
    "FSE_CREATE_DIR",
    "FSE_CHOWN",
    "FSE_XATTR_MODIFIED",
    "FSE_XATTR_REMOVED",
};

// argument names
static const char *kfseArgNames[] = {
    "FSE_ARG_UNKNOWN", "FSE_ARG_VNODE", "FSE_ARG_STRING", "FSE_ARGPATH",
    "FSE_ARG_INT32",   "FSE_ARG_INT64", "FSE_ARG_RAW",    "FSE_ARG_INO",
    "FSE_ARG_UID",     "FSE_ARG_DEV",   "FSE_ARG_MODE",   "FSE_ARG_GID",
    "FSE_ARG_FINFO",
};*/

// for pretty-printing of vnode types
enum vtype {
    VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VSTR, VCPLX
};

enum vtype iftovt_tab[] = {
    VNON, VFIFO, VCHR, VNON, VDIR,  VNON, VBLK, VNON,
    VREG, VNON,  VLNK, VNON, VSOCK, VNON, VNON, VBAD,
};

/*static const char *vtypeNames[] = {
    "VNON",  "VREG",  "VDIR", "VBLK", "VCHR", "VLNK",
    "VSOCK", "VFIFO", "VBAD", "VSTR", "VCPLX",
};
#define VTYPE_MAX (sizeof(vtypeNames)/sizeof(char *))
*/
/*static char *
get_proc_name(pid_t pid)
{
    size_t        len = sizeof(struct kinfo_proc);
    static int    name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    static struct kinfo_proc kp;
    
    name[3] = pid;
    
    kp.kp_proc.p_comm[0] = '\0';
    if (sysctl((int *)name, sizeof(name)/sizeof(*name), &kp, &len, NULL, 0))
        return "?";
    
    if (kp.kp_proc.p_comm[0] == '\0')
        return "exited?";
    
    return kp.kp_proc.p_comm;
}*/


int main(int argc, const char * argv[])
{

    @autoreleasepool {
       
        initPrivateLog();
        //TG: Now comes disk arbitration. Why? Because we need to know when a new drive is mounted so that we can scan it, too.
        DASessionRef session;
        session = DASessionCreate(kCFAllocatorDefault);        
        void *context = NULL;
        
        DARegisterDiskAppearedCallback(session,
                                       kDADiskDescriptionMatchVolumeMountable,
                                       diskAppearedHandler, context);
        dispatch_queue_t queueGlobalConcurrent = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        DASessionSetDispatchQueue(session, queueGlobalConcurrent);
        

        dispatch_queue_t queueMainQueue = dispatch_get_main_queue();
        dispatch_async(queueMainQueue, ^{
            //TG: Full disclosure: much of this logic is unchanged from Amit Singh's beautiful original program.
            //  I merely tacked on the clever bits to deal with malware and hashing. 
            setbuf(stdout, NULL);
            int32_t arg_id;
            int     fd, clonefd = -1;
            int     i, eoff, off, ret;
            struct stat fileStat;
            //int shouldHash = 0;
            char modeBuffer[MODE_STRING_LENGTH];
            char filenameBuffer [PATH_MAX];
            NSString *filenameString = [NSString string];
            
            kfs_event_arg_t *kea;
            struct           fsevent_clone_args fca;
            char             buffer[FSEVENT_BUFSIZ];
            //struct passwd   *p;
            //struct group    *g;
            //mode_t           va_mode;
            //u_int32_t        va_type;
            //u_int32_t        is_fse_arg_vnode = 0;
            //char             fileModeString[11 + 1];
            int8_t           event_list[] = { // action to take for each event
                FSE_REPORT,  // FSE_CREATE_FILE,
                FSE_REPORT,  // FSE_DELETE,
                FSE_REPORT,  // FSE_STAT_CHANGED,
                FSE_REPORT,  // FSE_RENAME,
                FSE_REPORT,  // FSE_CONTENT_MODIFIED,
                FSE_REPORT,  // FSE_EXCHANGE,
                FSE_REPORT,  // FSE_FINDER_INFO_CHANGED,
                FSE_REPORT,  // FSE_CREATE_DIR,
                FSE_REPORT,  // FSE_CHOWN,
                FSE_REPORT,  // FSE_XATTR_MODIFIED,
                FSE_REPORT,  // FSE_XATTR_REMOVED,
            };
            
            if (argc != 1) {
                fprintf(stderr, "%s (%s)\n", PROGNAME, PROGVERS);
                fprintf(stderr, "Copyright (c) 2008 Amit Singh. Portions copyright (c) 2014 Terence Goggin."
                        "All Rights Reserved.\n");
                fprintf(stderr, "File system change logger for Mac OS X. Usage:\n");
                fprintf(stderr, "\n\t%s\n\n", PROGNAME);
                fprintf(stderr, "%s does not take any arguments. "
                        "It must be run as root.\n\n", PROGNAME);
                
                exit(1);
                exit(1);
            }
            
            if (geteuid() != 0) {
                fprintf(stderr, "You must be root to run %s. Try again using 'sudo'.\n",
                        PROGNAME);
                exit(1);
            }
        
            if ((fd = open(DEV_FSEVENTS, O_RDONLY)) < 0) {
                perror("open");
                exit(1);
            }
            
            fca.event_list = (int8_t *)event_list;
            fca.num_events = sizeof(event_list)/sizeof(int8_t);
            fca.event_queue_depth = EVENT_QUEUE_SIZE;
            fca.fd = &clonefd;
            if ((ret = ioctl(fd, FSEVENTS_CLONE, (char *)&fca)) < 0) {
                perror("ioctl");
                close(fd);
                exit(1);
            }
            
            close(fd);
            printf("fsevents device cloned (fd %d)\nfslogger ready\n", clonefd);
            
            if ((ret = ioctl(clonefd, FSEVENTS_WANT_EXTENDED_INFO, NULL)) < 0) {
                perror("ioctl");
                close(clonefd);
                exit(1);
            }
            
            
            while (1) { // event processing loop
                
                if ((ret = read(clonefd, buffer, FSEVENT_BUFSIZ)) > 0){
                    //printf("=> received %d bytes\n", ret);
                }
                
                off = 0;
                
                while (off < ret) { // process one or more events received
                    
                    struct kfs_event *kfse = (struct kfs_event *)((char *)buffer + off);
                    
                    off += sizeof(int32_t) + sizeof(pid_t); // type + pid
                    
                    if (kfse->type == FSE_EVENTS_DROPPED) { // special event
                        //printf("# Event\n");
                        //printf("  %-14s = %s\n", "type", "EVENTS DROPPED");
                        //printf("  %-14s = %d\n", "pid", kfse->pid);
                        off += sizeof(u_int16_t); // FSE_ARG_DONE: sizeof(type)
                        continue;
                    }
                    
                    int32_t atype = kfse->type & FSE_TYPE_MASK;
                    uint32_t aflags = FSE_GET_FLAGS(kfse->type);
                    
                    if ((atype < FSE_MAX_EVENTS) && (atype >= -1))  {
                        //printf("# Event\n");
                        //printf("  %-14s = %s\n", "type", kfseNames[atype]);
                        if (aflags & FSE_COMBINED_EVENTS) {
                            //printf("%s", ", combined events");
                        }
                        if (aflags & FSE_CONTAINS_DROPPED_EVENTS) {
                            //printf("%s", ", contains dropped events");
                        }
                        //printf("\n");
                    } else { // should never happen
                        //printf("This may be a program bug (type = %d).\n", atype);
                        exit(1);
                    }
                    
                    //printf("  %-14s = %d (%s)\n", "pid", kfse->pid,
                    //       get_proc_name(kfse->pid));
                    //printf("  # Details\n    # %-14s%4s  %s\n", "type", "len", "data");
                    
                    kea = kfse->args;
                    i = 0;
                    
                    //while ((off < ret, (i <= FSE_MAX_ARGS)) { // process arguments
                    while (off < ret) {
                        
                        i++;
                        
                        if (kea->type == FSE_ARG_DONE) { // no more arguments
                            //printf("    %s (%#x)\n", "FSE_ARG_DONE", kea->type);
                            off += sizeof(u_int16_t);
                            break;
                        }
                        
                        eoff = sizeof(kea->type) + sizeof(kea->len) + kea->len;
                        off += eoff;
                        
                        arg_id = (kea->type > FSE_MAX_ARGS) ? 0 : kea->type;
                        //printf("    %-16s%4hd  ", kfseArgNames[arg_id], kea->len);
                        
                        switch (kea->type) { // handle based on argument type
                                
                            case FSE_ARG_VNODE:  // a vnode (string) pointer
                                //is_fse_arg_vnode = 1;
                                //printf("%-6s = %s\n", "path", (char *)&(kea->data.vp));
                                break;
                                
                            case FSE_ARG_STRING: // a string pointer
                                //printf("%-6s = %s\n", "string", (char *)&(kea->data.str)-4);
                                memset(&filenameBuffer, 0, sizeof(filenameBuffer)); //if there's a path, capture it for hashing purposes.
                                sprintf((char *)&filenameBuffer, "%s", (char *)&(kea->data.str)-4);
                                filenameString = [NSString stringWithUTF8String: (char *)&(kea->data.str)-4];
                                break;
                                
                            case FSE_ARG_INT32:
                                //printf("%-6s = %d\n", "int32", kea->data.int32);
                                break;
                                
                            case FSE_ARG_RAW: // a void pointer
                                /*printf("%-6s = ", "ptr");
                                for (j = 0; j < kea->len; j++)
                                    printf("%02x ", ((char *)kea->data.ptr)[j]);
                                printf("\n");*/
                                break;
                                
                            case FSE_ARG_INO: // an inode number
                                //printf("%-6s = %d\n", "ino", (int)kea->data.ino);
                                break;
                                
                            case FSE_ARG_UID: // a user ID
                                //p = getpwuid(kea->data.uid);
                                //printf("%-6s = %d (%s)\n", "uid", kea->data.uid,
                                //       (p) ? p->pw_name : "?");
                                break;
                                
                            case FSE_ARG_DEV: // a file system ID or a device number
                                /*if (is_fse_arg_vnode) {
                                    printf("%-6s = %#08x\n", "fsid", kea->data.dev);
                                    is_fse_arg_vnode = 0;
                                } else {
                                    printf("%-6s = %#08x (major %u, minor %u)\n",
                                           "dev", kea->data.dev,
                                           major(kea->data.dev), minor(kea->data.dev));
                                }*/
                                break;
                                
                            case FSE_ARG_MODE: // a combination of file mode and file type
                                //mode = *((int32_t *) (in_buf + pos));
                                //get_mode_string(mode, buffer);
                                break;
                                
                            case FSE_ARG_GID: // a group ID
                                //g = getgrgid(kea->data.gid);
                                //printf("%-6s = %d (%s)\n", "gid", kea->data.gid,
                                //       (g) ? g->gr_name : "?");
                                break;
                                
                            case FSE_ARG_INT64: // timestamp
                                //printf("%-6s = %llu\n", "tstamp", kea->data.timestamp);
                                break;
                                
                            default:
                                //printf("%-6s = ?\n", "unknown");
                                break;
                        }
                        
                        kea = (kfs_event_arg_t *)((char *)kea + eoff); // next
                    } // for each argument
                    if (stat((char *)filenameBuffer, &fileStat) ) {
                        //TG: if stat fails, the file was probably moved or deleted before we could get to it.
                        //  This is quite common with Archive Utility (and maybe other temporary files) and shouldn't be regarded as
                        //  inherently suspect.
                        //  Could log it though, if extremely paranoid, I suppose.
                    }
                    else {
                        get_mode_string(fileStat.st_mode, modeBuffer);
                        if ( ((nil != strstr(modeBuffer, "x") ) || hasForbiddenExtension(filenameString))
                                && S_ISREG(fileStat.st_mode)){
                            doHash(filenameString);
                        }
                        else if (S_ISDIR(fileStat.st_mode)) {
                            //TG: these events are frequently triggered by Archive Manager; Archive Manager unzips archives thusly:
                            //  1 - Creating actual destination folder (i.e., ~/Downloads/zipfilename
                            //  2 - Unpacking contents to temp folder in /var/private/...
                            //  3 - moving unpacked zip, etc. contents back into the final dest. folder
                            //  This creates a problem for us in that we get the file creation events for the items in /var/private, but they are moved before we could hash/quarantine them.
                            //  Therefore, when we get a directory-level event, we must enumerate contents of directory and pass them through the hashing logic.
                            //  This is also of course useful for scanning a newly-mounted volume.
                            directoryDoHash(filenameString);
                        }
                    }
                } // for each event
            } // forever
        
            close(clonefd);

            releasePrivateLog();
        });
        dispatch_main();
        DASessionSetDispatchQueue(session, NULL);
        CFRelease(session);
    }

    return 0;
}



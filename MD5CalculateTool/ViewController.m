//
//  ViewController.m
//  MD5CalculateTool
//
//  Created by tangzhi on 2017/7/13.
//  Copyright © 2017年 tangzhi. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonDigest.h>

@implementation ViewController
{
    __weak IBOutlet NSTextField *docPath;
    __weak IBOutlet NSTextField *md5Str;
    
}

- (void)viewDidLoad {
    [super viewDidLoad];

    // Do any additional setup after loading the view.
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

- (IBAction)sltDocment:(id)sender {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setMessage:@""];
    [panel setPrompt:@"OK"];
    [panel setCanChooseDirectories:YES];
    [panel setCanCreateDirectories:YES];
    [panel setCanChooseFiles:YES];
    NSString *path_all =  @"";
    NSInteger result = [panel runModal];
    if (result == NSFileHandlingPanelOKButton)
    {
        path_all = [[panel URL] path];
        NSLog(@"%@", path_all);
        docPath.stringValue = path_all;
        md5Str.stringValue = [NSString stringWithFormat:@"MD5：%@",[self getFileMD5WithPath:path_all]];
    }
}

//保存文件
- (void)savePath {
    NSSavePanel*    panel = [NSSavePanel savePanel];
    
    NSView *viewExt = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 180, 40)];
    
    NSTextField *labExt = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 10, 80, 20)];
    
    [labExt setBordered:NO];
    
    [labExt setDrawsBackground:NO];
    
    labExt.stringValue = @"File type: ";
    
    NSComboBox *cbExt = [[NSComboBox alloc] initWithFrame:NSMakeRect(80, 8, 100, 25)];
    //[cbExt addItemsWithObjectValues:@[@".bmp", @".jpg", @".png", @".tif"]];
    [cbExt addItemsWithObjectValues:@[@".txt"]];
    cbExt.stringValue = @".txt";
    
    [viewExt addSubview:labExt];
    
    [viewExt addSubview:cbExt];
    
    [panel setAccessoryView:viewExt];
    
    NSInteger result = [panel runModal];
    if (result == NSFileHandlingPanelOKButton)
    {
        NSString *path = [[panel URL] path];
        NSLog(@"%@", path);
    }
}


#pragma mark MD5
#define FileHashDefaultChunkSizeForReadingData 1024*8
-(NSString*)getFileMD5WithPath:(NSString*)path
{
    return (__bridge_transfer NSString *)FileMD5HashCreateWithPath((__bridge CFStringRef)path, FileHashDefaultChunkSizeForReadingData);
}

CFStringRef FileMD5HashCreateWithPath(CFStringRef filePath,size_t chunkSizeForReadingData) {
    // Declare needed variables
    CFStringRef result = NULL;
    CFReadStreamRef readStream = NULL;
    
    // Get the file URL
    CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                     (CFStringRef)filePath,
                                                     kCFURLPOSIXPathStyle,
                                                     (Boolean)false);
    if (!fileURL){
        if (fileURL) {
            CFRelease(fileURL);
        }
        return result;
    }
    // Create and open the read stream
    readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault,(CFURLRef)fileURL);
    if (!readStream){
        if (readStream) {
            CFReadStreamClose(readStream);
            CFRelease(readStream);
        }
        
        if (fileURL) {
            CFRelease(fileURL);
        }
        return result;
    }
    bool didSucceed = (bool)CFReadStreamOpen(readStream);
    if (!didSucceed){
        if (readStream) {
            CFReadStreamClose(readStream);
            CFRelease(readStream);
        }
        
        if (fileURL) {
            CFRelease(fileURL);
        }
        return result;
    }
    
    // Initialize the hash object
    CC_MD5_CTX hashObject;
    CC_MD5_Init(&hashObject);
    // Make sure chunkSizeForReadingData is valid
    if (!chunkSizeForReadingData) {
        chunkSizeForReadingData = FileHashDefaultChunkSizeForReadingData;
    }
    
    // Feed the data to the hash object
    bool hasMoreData = true;
    while (hasMoreData) {
        uint8_t buffer[chunkSizeForReadingData];
        CFIndex readBytesCount = CFReadStreamRead(readStream,(UInt8 *)buffer,(CFIndex)sizeof(buffer));
        if (readBytesCount == -1) break;
        if (readBytesCount == 0) {
            hasMoreData = false;
            continue;
        }
        CC_MD5_Update(&hashObject,(const void *)buffer,(CC_LONG)readBytesCount);
    }
    
    // Check if the read operation succeeded
    didSucceed = !hasMoreData;
    
    // Compute the hash digest
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(digest, &hashObject);
    
    // Abort if the read operation failed
    if (!didSucceed){
        if (readStream) {
            CFReadStreamClose(readStream);
            CFRelease(readStream);
        }
        
        if (fileURL) {
            CFRelease(fileURL);
        }
        return result;
    }
    
    // Compute the string result
    char hash[2 * sizeof(digest) + 1];
    for (size_t i = 0; i < sizeof(digest); ++i) {
        snprintf(hash + (2 * i), 3, "%02x", (int)(digest[i]));
    }
    
    result = CFStringCreateWithCString(kCFAllocatorDefault,(const char *)hash,kCFStringEncodingUTF8);
    
done_label:
    if (readStream) {
        CFReadStreamClose(readStream);
        CFRelease(readStream);
    }
    
    if (fileURL) {
        CFRelease(fileURL);
    }
    return result;
}

@end

#import "RootDetection.h"
#import "Cordova/CDV.h"
#include <string.h>
#import <mach-o/loader.h>
#import <mach-o/dyld.h>
#import <mach-o/arch.h>
#import <objc/runtime.h>



@implementation RootDetection

- (void)pluginInitialize{
    bool jailbroken = ![[self jailbroken] isEqualToString:@"SAFE"];
    if(jailbroken)
    exit(0);
}

- (void)detect:(CDVInvokedUrlCommand *)command {
    CDVPluginResult *pluginResult;

    @try
    {
        NSString *result =[self jailbroken];
        bool jailbroken = ![[self jailbroken] isEqualToString:@"SAFE"];
        // NSLog(jailbroken ? @"Yes root!" : @"No no-root!");
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:jailbroken];
    }
    @catch (NSException *exception)
    {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
    }
    @finally
    {
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (NSString *) jailbroken {
#if !(TARGET_IPHONE_SIMULATOR)
    // Check 1 : existence of files that are common for jailbroken devices
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"] ||
        [[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"] ||
        [[NSFileManager defaultManager] fileExistsAtPath:@"/bin/bash"] ||
        [[NSFileManager defaultManager] fileExistsAtPath:@"/usr/bin/apt"] ||
        [[NSFileManager defaultManager] fileExistsAtPath:@"/usr/sbin/sshd"] ||
        [[NSFileManager defaultManager] fileExistsAtPath:@"/etc/apt"] ||
        [[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/lib/apt/"] ||
        [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]) {
        return @"UNSAFE";
    }
    FILE *f = NULL ;
    if ((f = fopen("/bin/bash", "r")) ||
        (f = fopen("/Applications/Cydia.app", "r")) ||
        (f = fopen("/Library/MobileSubstrate/MobileSubstrate.dylib", "r")) ||
        (f = fopen("/usr/sbin/sshd", "r")) ||
        (f = fopen("/etc/apt", "r"))) {
        fclose(f);
        return @"UNSAFE";
    }
    fclose(f);
    // Check 2 : Reading and writing in system directories (sandbox violation)
    NSError *error;
    NSString *stringToBeWritten = @"Jailbreak Test.";
    [stringToBeWritten writeToFile:@"/private/jailbreak.txt" atomically:YES
                          encoding:NSUTF8StringEncoding error:&error];
    if(error==nil){
        //Device is jailbroken
        return @"UNSAFE";
    } else {
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/jailbreak.txt" error:nil];
    }
    NSString *detectResult =[self detect];
    if(![detectResult isEqualToString:@"SAFE"]){
        return @"UNSAFE";
    }
    NSString *debugResult =[self checkDebug];
    if(![debugResult isEqualToString:@"SAFE"]){
        return @"UNSAFE";
    }
#endif
    return @"SAFE";
}

- (NSString *) detect {
    
    //Get count of all currently loaded DYLD
    uint32_t count = _dyld_image_count();


    for(uint32_t i = 0; i < count; i++)
    {

        NSString *name = [[NSString alloc]initWithUTF8String:_dyld_get_image_name(i)];
        if([name rangeOfString:@"frida" options:NSCaseInsensitiveSearch].location != NSNotFound)
        {
            return @"UNSAFE";
        }
       
    }
    return @"SAFE";
    }

- (NSString *) checkDebug {
    
    if( getppid() != 1){
        return @"UNSAFE";
    }
    return @"SAFE";
}

@end

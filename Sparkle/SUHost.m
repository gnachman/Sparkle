//
//  SUHost.m
//  Sparkle
//
//  Copyright 2008 Andy Matuschak. All rights reserved.
//

#import "SUHost.h"

#import "SUConstants.h"
#include <sys/mount.h> // For statfs for isRunningOnReadOnlyVolume
#import "SULog.h"
#import "SUSignatures.h"

#include "AppKitPrevention.h"

NS_ASSUME_NONNULL_BEGIN

// This class should not rely on AppKit and should also be process independent
// For example, it should not have code that tests writabilty to somewhere on disk,
// as that may depend on the privileges of the process owner. Or code that depends on
// if the process is sandboxed or not; eg: finding the user's caches directory. Or code that depends
// on compilation flags and if other files exist relative to the host bundle.

@interface SUHost ()

@property (strong, readwrite) NSBundle *bundle;
@property (nonatomic, readonly) BOOL isMainBundle;
@property (copy, nullable) NSString *defaultsDomain;
@property (assign) BOOL usesStandardUserDefaults;
// The NSUserDefaults instance used when usesStandardUserDefaults is YES. This is
// [NSUserDefaults standardUserDefaults] normally, but an isolated suite when the
// process was launched with "-suite <name>" (iTerm2 fork). See SUCurrentSuiteName().
@property (strong) NSUserDefaults *standardUserDefaultsOrSuite;
@property (readonly, copy, nullable) NSString *publicDSAKey;

@end

@implementation SUHost

@synthesize bundle;
@synthesize isMainBundle = _isMainBundle;
@synthesize defaultsDomain;
@synthesize usesStandardUserDefaults;

- (instancetype)initWithBundle:(NSBundle *)aBundle
{
	if ((self = [super init]))
	{
        NSParameterAssert(aBundle);
        self.bundle = aBundle;
        if (![self.bundle bundleIdentifier]) {
            SULog(SULogLevelError, @"Error: the bundle being updated at %@ has no %@! This will cause preference read/write to not work properly.", self.bundle, kCFBundleIdentifierKey);
        }
        
        _isMainBundle = [aBundle isEqualTo:[NSBundle mainBundle]];

        self.defaultsDomain = [self objectForInfoDictionaryKey:SUDefaultsDomainKey];
        if (!self.defaultsDomain) {
            self.defaultsDomain = [self.bundle bundleIdentifier];
        }

        // If we're using the main bundle's defaults we'll use the standard user defaults mechanism, otherwise we have to get CF-y.
        NSString *mainBundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
        usesStandardUserDefaults = !self.defaultsDomain || [self.defaultsDomain isEqualToString:mainBundleIdentifier];

        // iTerm2 fork: when launched with "-suite <name>", route Sparkle's user
        // defaults into that private suite so an isolated test instance doesn't
        // read or clobber the production instance's Sparkle settings. When no
        // suite is present (the normal case) this is exactly the standard defaults,
        // so behavior is unchanged. Only the standardUserDefaults path is affected;
        // the CFPreferences path (a custom SUDefaultsDomain) is left untouched.
        NSString *suiteName = SUCurrentSuiteName();
        if (suiteName != nil) {
            self.standardUserDefaultsOrSuite = [[NSUserDefaults alloc] initWithSuiteName:suiteName];
        } else {
            self.standardUserDefaultsOrSuite = [NSUserDefaults standardUserDefaults];
        }
    }
    return self;
}


- (NSString *)description { return [NSString stringWithFormat:@"%@ <%@>", [self class], [self bundlePath]]; }

- (NSString *)bundlePath
{
    return [self.bundle bundlePath];
}

- (NSString *)name
{
    NSString *name;

    // Allow host bundle to provide a custom name
    name = [self objectForInfoDictionaryKey:@"SUBundleName"];
    if (name && name.length > 0) return name;

    name = [self objectForInfoDictionaryKey:@"CFBundleDisplayName"];
	if (name && name.length > 0) return name;

    name = [self objectForInfoDictionaryKey:(__bridge NSString *)kCFBundleNameKey];
	if (name && name.length > 0) return name;

    return [[[NSFileManager defaultManager] displayNameAtPath:[self bundlePath]] stringByDeletingPathExtension];
}

- (NSString *)version
{
    NSString *version = [self objectForInfoDictionaryKey:(__bridge NSString *)kCFBundleVersionKey];
    if (!version || [version isEqualToString:@""])
        [NSException raise:@"SUNoVersionException" format:@"This host (%@) has no %@! This attribute is required.", [self bundlePath], (__bridge NSString *)kCFBundleVersionKey];
    return version;
}

- (NSString *)displayVersion
{
    NSString *shortVersionString = [self objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    if (shortVersionString)
        return shortVersionString;
    else
        return [self version]; // Fall back on the normal version string.
}

- (BOOL)isRunningOnReadOnlyVolume
{
    struct statfs statfs_info;
    statfs([[self.bundle bundlePath] fileSystemRepresentation], &statfs_info);
    return (statfs_info.f_flags & MNT_RDONLY) != 0;
}

- (BOOL)isRunningTranslocated
{
    NSString *path = [self.bundle bundlePath];
    return [path rangeOfString:@"/AppTranslocation/"].location != NSNotFound;
}


- (NSString *__nullable)publicEDKey
{
    return [self objectForInfoDictionaryKey:SUPublicEDKeyKey];
}

- (NSString *__nullable)publicDSAKey
{
    // Maybe the key is just a string in the Info.plist.
    NSString *key = [self objectForInfoDictionaryKey:SUPublicDSAKeyKey];
	if (key) {
        return key;
    }

    // More likely, we've got a reference to a Resources file by filename:
    NSString *keyFilename = [self publicDSAKeyFileKey];
	if (!keyFilename) {
        return nil;
    }

    NSString *keyPath = [self.bundle pathForResource:keyFilename ofType:nil];
    if (!keyPath) {
        return nil;
    }
    NSError *error = nil;
    key = [NSString stringWithContentsOfFile:keyPath encoding:NSASCIIStringEncoding error:&error];
    if (error) {
        SULog(SULogLevelError, @"Error loading %@: %@", keyPath, error);
    }
    return key;
}

- (SUPublicKeys *)publicKeys
{
    return [[SUPublicKeys alloc] initWithDsa:[self publicDSAKey] ed:[self publicEDKey]];
}

- (NSString * __nullable)publicDSAKeyFileKey
{
    return [self objectForInfoDictionaryKey:SUPublicDSAKeyFileKey];
}

- (nullable id)objectForInfoDictionaryKey:(NSString *)key
{
    if (self.isMainBundle) {
        // Common fast path - if we're updating the main bundle, that means our updater and host bundle's lifetime is the same
        // If the bundle happens to be updated or change, that means our updater process needs to be terminated first to do it safely
        // Thus we can rely on the cached Info dictionary
        return [self.bundle objectForInfoDictionaryKey:key];
    } else {
        // Slow path - if we're updating another bundle, we should read in the most up to date Info dictionary because
        // the bundle can be replaced externally or even by us.
        // This is the easiest way to read the Info dictionary values *correctly* despite some performance loss.
        // A mutable method to reload the Info dictionary at certain points and have it cached at other points is challenging to do correctly.
        CFDictionaryRef cfInfoDictionary = CFBundleCopyInfoDictionaryInDirectory((CFURLRef)self.bundle.bundleURL);
        NSDictionary *infoDictionary = CFBridgingRelease(cfInfoDictionary);
        
        return [infoDictionary objectForKey:key];
    }
}

- (BOOL)boolForInfoDictionaryKey:(NSString *)key
{
    return [(NSNumber *)[self objectForInfoDictionaryKey:key] boolValue];
}

- (nullable id)objectForUserDefaultsKey:(NSString *)defaultName
{
    if (!defaultName || !self.defaultsDomain) {
        return nil;
    }

    // Under Tiger, CFPreferencesCopyAppValue doesn't get values from NSRegistrationDomain, so anything
    // passed into -[NSUserDefaults registerDefaults:] is ignored.  The following line falls
    // back to using NSUserDefaults, but only if the host bundle is the main bundle.
    if (self.usesStandardUserDefaults) {
        return [self.standardUserDefaultsOrSuite objectForKey:defaultName];
    }

    CFPropertyListRef obj = CFPreferencesCopyAppValue((__bridge CFStringRef)defaultName, (__bridge CFStringRef)self.defaultsDomain);
    return CFBridgingRelease(obj);
}

// Note this handles nil being passed for defaultName, in which case the user default will be removed
- (void)setObject:(nullable id)value forUserDefaultsKey:(NSString *)defaultName
{
	if (self.usesStandardUserDefaults)
	{
        [self.standardUserDefaultsOrSuite setObject:value forKey:defaultName];
	}
	else
	{
        CFPreferencesSetValue((__bridge CFStringRef)defaultName, (__bridge CFPropertyListRef)(value), (__bridge CFStringRef)self.defaultsDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        CFPreferencesSynchronize((__bridge CFStringRef)self.defaultsDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    }
}

- (BOOL)boolForUserDefaultsKey:(NSString *)defaultName
{
    if (self.usesStandardUserDefaults) {
        return [self.standardUserDefaultsOrSuite boolForKey:defaultName];
    }

    BOOL value;
    CFPropertyListRef plr = CFPreferencesCopyAppValue((__bridge CFStringRef)defaultName, (__bridge CFStringRef)self.defaultsDomain);
    if (plr == NULL) {
        value = NO;
	}
	else
	{
        value = (BOOL)CFBooleanGetValue((CFBooleanRef)plr);
        CFRelease(plr);
    }
    return value;
}

- (void)setBool:(BOOL)value forUserDefaultsKey:(NSString *)defaultName
{
	if (self.usesStandardUserDefaults)
	{
        [self.standardUserDefaultsOrSuite setBool:value forKey:defaultName];
	}
	else
	{
        CFPreferencesSetValue((__bridge CFStringRef)defaultName, (__bridge CFBooleanRef) @(value), (__bridge CFStringRef)self.defaultsDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        CFPreferencesSynchronize((__bridge CFStringRef)self.defaultsDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    }
}

- (nullable id)objectForKey:(NSString *)key {
    return [self objectForUserDefaultsKey:key] ? [self objectForUserDefaultsKey:key] : [self objectForInfoDictionaryKey:key];
}

- (BOOL)boolForKey:(NSString *)key {
    return [self objectForUserDefaultsKey:key] ? [self boolForUserDefaultsKey:key] : [self boolForInfoDictionaryKey:key];
}

@end

NS_ASSUME_NONNULL_END

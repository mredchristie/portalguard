package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework CoreWLAN -framework CoreLocation -framework Security
#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
#import <CoreLocation/CoreLocation.h>
#import <Security/Security.h>
#include <stdlib.h>

static CLLocationManager *pgLocation;

// The manager lives on the main thread, where macOS delivers its answers.
static void pgEnsureManager(void) {
	if (pgLocation) return;
	if ([NSThread isMainThread]) {
		pgLocation = [[CLLocationManager alloc] init];
	} else {
		dispatch_sync(dispatch_get_main_queue(), ^{ pgLocation = [[CLLocationManager alloc] init]; });
	}
}

// 0 not asked yet, 1 restricted, 2 denied, 3 or 4 allowed.
static int pgLocationStatus(void) {
	pgEnsureManager();
	return (int)pgLocation.authorizationStatus;
}

// Asks, once: macOS shows its prompt the first time and remembers the answer.
static void pgRequestLocation(void) {
	pgEnsureManager();
	dispatch_async(dispatch_get_main_queue(), ^{
		[pgLocation requestWhenInUseAuthorization];
		// On macOS the prompt is tied to a request for location itself.
		[pgLocation startUpdatingLocation];
		dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
			[pgLocation stopUpdatingLocation];
		});
	});
}

// A scan, as JSON: the current network, and every one in range. Names are
// empty unless Location is allowed; that is macOS's rule, not ours.
static char *pgScan(void) {
	@autoreleasepool {
		CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
		if (!iface) return strdup("{\"error\":\"this Mac has no Wi-Fi\"}");
		NSError *err = nil;
		NSSet<CWNetwork *> *nets = [iface scanForNetworksWithName:nil error:&err];
		// A scan that clashes with one macOS is already running fails with
		// "resource busy". Wait and try again, then settle for what macOS's
		// own last scan found, which is seconds old at most. Seen at EE WiFi,
		// on the first scan after opening the app.
		for (int i = 0; i < 3 && err && nets.count == 0; i++) {
			[NSThread sleepForTimeInterval:1.0];
			err = nil;
			nets = [iface scanForNetworksWithName:nil error:&err];
		}
		if (err && nets.count == 0) {
			NSSet<CWNetwork *> *cached = [iface cachedScanResults];
			if (cached.count > 0) {
				nets = cached;
				err = nil;
			}
		}
		NSMutableArray *list = [NSMutableArray array];
		for (CWNetwork *n in nets) {
			BOOL open = [n supportsSecurity:kCWSecurityNone];
			if (@available(macOS 12.0, *)) {
				open = open || [n supportsSecurity:kCWSecurityOWE];
			}
			[list addObject:@{
				@"ssid": n.ssid ?: @"",
				@"rssi": @(n.rssiValue),
				@"open": @(open),
			}];
		}
		NSDictionary *out = @{
			@"current": iface.ssid ?: @"",
			@"power": @(iface.powerOn),
			@"networks": list,
			@"error": err ? err.localizedDescription : @"",
		};
		NSData *data = [NSJSONSerialization dataWithJSONObject:out options:0 error:nil];
		NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
		return strdup(s.UTF8String);
	}
}
// PortalGuard's own copy of a network's password, in the login keychain.
// macOS keeps Wi-Fi passwords in the System keychain, and reading one from
// there asks for an administrator's name and password every time, with no
// "Always Allow". So that is asked once per network, and the copy, which only
// this app may read, is used from then on.
static NSString *const pgRejoinService = @"dev.mredchristie.portalguard.rejoin";

static NSString *pgOwnPassword(NSString *ssid) {
	NSDictionary *q = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
		(__bridge id)kSecAttrService: pgRejoinService,
		(__bridge id)kSecAttrAccount: ssid,
		(__bridge id)kSecReturnData: @YES,
	};
	CFTypeRef out = NULL;
	if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &out) != errSecSuccess || !out) return nil;
	NSData *data = (__bridge_transfer NSData *)out;
	return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static NSDictionary *pgOwnItem(NSString *ssid) {
	return @{
		(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
		(__bridge id)kSecAttrService: pgRejoinService,
		(__bridge id)kSecAttrAccount: ssid,
	};
}

static void pgForget(NSString *ssid) {
	SecItemDelete((__bridge CFDictionaryRef)pgOwnItem(ssid));
}

static void pgKeepPassword(NSString *ssid, NSString *password) {
	pgForget(ssid);
	NSMutableDictionary *add = [pgOwnItem(ssid) mutableCopy];
	add[(__bridge id)kSecAttrLabel] = [NSString stringWithFormat:@"PortalGuard: rejoin %@", ssid];
	add[(__bridge id)kSecValueData] = [password dataUsingEncoding:NSUTF8StringEncoding];
	SecItemAdd((__bridge CFDictionaryRef)add, NULL);
}

// Rejoins a saved network by name: its password from PortalGuard's own copy,
// or the first time from macOS's (which asks the user), then an association
// through CoreWLAN. Returns NULL on success, or why not (the caller frees it).
static char *pgRejoin(const char *cssid) {
	@autoreleasepool {
		CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
		if (!iface) return strdup("this Mac has no Wi-Fi");
		NSString *ssid = [NSString stringWithUTF8String:cssid];
		NSData *ssidData = [ssid dataUsingEncoding:NSUTF8StringEncoding];
		NSError *err = nil;
		NSSet<CWNetwork *> *nets = [iface scanForNetworksWithSSID:ssidData error:&err];
		CWNetwork *net = nets.anyObject;
		if (!net) return strdup([[NSString stringWithFormat:@"%@ is not in range", ssid] UTF8String]);
		NSString *password = nil;
		BOOL own = NO;
		if (![net supportsSecurity:kCWSecurityNone]) {
			password = pgOwnPassword(ssid);
			own = password != nil;
		}
		if (!own && ![net supportsSecurity:kCWSecurityNone]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
			OSStatus st = CWKeychainFindWiFiPassword(kCWKeychainDomainSystem, ssidData, &password);
			if (st != errSecSuccess) {
				st = CWKeychainFindWiFiPassword(kCWKeychainDomainUser, ssidData, &password);
			}
#pragma clang diagnostic pop
			if (st != errSecSuccess || !password) {
				return strdup([[NSString stringWithFormat:@"no saved password for %@ that PortalGuard may use", ssid] UTF8String]);
			}
		}
		if (![iface associateToNetwork:net password:password error:&err]) {
			// A copy that no longer works (the password was changed): drop
			// it, so the next rejoin asks macOS again.
			if (own) pgForget(ssid);
			return strdup([[NSString stringWithFormat:@"could not rejoin %@: %@", ssid, err.localizedDescription] UTF8String]);
		}
		if (password && !own) pgKeepPassword(ssid, password);
		return NULL;
	}
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"sort"
	"unsafe"
)

// Network is one Wi-Fi network in range, for the list.
type Network struct {
	SSID    string `json:"ssid"`
	RSSI    int    `json:"rssi"`
	Open    bool   `json:"open"`
	Current bool   `json:"current"`
}

// Scan is what the list shows: the networks in range, and why there are none
// when there are none.
type Scan struct {
	// Location is "allowed", "ask" (not asked yet), "denied" or "restricted".
	Location string    `json:"location"`
	Power    bool      `json:"power"`
	Current  string    `json:"current"`
	Networks []Network `json:"networks"`
	// Hidden is how many networks were found whose names macOS withheld.
	Hidden int    `json:"hidden"`
	Error  string `json:"error,omitempty"`
}

func locationStatus() string {
	switch C.pgLocationStatus() {
	case 0:
		return "ask"
	case 1:
		return "restricted"
	case 2:
		return "denied"
	default:
		return "allowed"
	}
}

func requestLocation() { C.pgRequestLocation() }

func scanWiFi() Scan {
	s := Scan{Location: locationStatus()}
	cs := C.pgScan()
	defer C.free(unsafe.Pointer(cs))
	var raw struct {
		Current  string    `json:"current"`
		Power    bool      `json:"power"`
		Networks []Network `json:"networks"`
		Error    string    `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(cs)), &raw); err != nil {
		s.Error = err.Error()
		return s
	}
	s.Power, s.Current, s.Error = raw.Power, raw.Current, raw.Error
	s.Networks, s.Hidden = tidy(raw.Networks, raw.Current)
	return s
}

// tidy keeps one entry per name, the strongest, strongest first, and counts
// the ones whose names were withheld.
func tidy(in []Network, current string) ([]Network, int) {
	best := map[string]Network{}
	hidden := 0
	for _, n := range in {
		if n.SSID == "" {
			hidden++
			continue
		}
		if b, ok := best[n.SSID]; !ok || n.RSSI > b.RSSI {
			n.Open = n.Open || (ok && b.Open)
			best[n.SSID] = n
		}
	}
	out := make([]Network, 0, len(best))
	for _, n := range best {
		n.Current = n.SSID == current && current != ""
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RSSI != out[j].RSSI {
			return out[i].RSSI > out[j].RSSI
		}
		return out[i].SSID < out[j].SSID
	})
	return out, hidden
}

// rejoinWiFi puts the Mac back on the saved network ssid. See pgRejoin.
func rejoinWiFi(ssid string) error {
	cs := C.CString(ssid)
	defer C.free(unsafe.Pointer(cs))
	if e := C.pgRejoin(cs); e != nil {
		defer C.free(unsafe.Pointer(e))
		return errors.New(C.GoString(e))
	}
	return nil
}

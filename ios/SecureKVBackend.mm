#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#include "../cpp/SecureKVBackend.h"

#include <stdexcept>
#include <string>

// iOS backend for secureKV. Stores arbitrary byte values as
// kSecClassGenericPassword Keychain items, scoped per-app via
// kSecAttrService = "<bundleId>.cryptolib.kv". Items are accessible only
// while the device is unlocked and never sync to iCloud or device-to-device
// transfer (kSecAttrAccessibleWhenUnlockedThisDeviceOnly).

namespace facebook::react::cryptolib {
namespace {

// Per-process cache of authenticated LAContext objects, keyed by the
// secureKV alias. Within a successful LAContext's
// touchIDAuthenticationAllowableReuseDuration window, iOS skips the
// biometric prompt for any SecItemCopyMatching that takes the same
// LAContext via kSecUseAuthenticationContext. Cache survives until the
// process dies.
NSMutableDictionary<NSString*, LAContext*>* laContextCache() {
  static NSMutableDictionary<NSString*, LAContext*>* cached = nil;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    cached = [[NSMutableDictionary alloc] init];
  });
  return cached;
}

// Apple caps `touchIDAuthenticationAllowableReuseDuration` at
// LATouchIDAuthenticationMaximumAllowableReuseDuration (300 seconds).
// Larger values are silently clamped by the framework; we mirror the
// cap explicitly so the JS-side semantics match what iOS will actually
// honour, and so the caller learns about the cap via a one-shot log.
static const uint32_t kMaxReuseDurationSec = 300;

LAContext* contextForRead(NSString* alias, uint32_t windowSec) {
  uint32_t effective = windowSec;
  if (windowSec > kMaxReuseDurationSec) {
    static dispatch_once_t warnOnce;
    dispatch_once(&warnOnce, ^{
      NSLog(
        @"[secureKV] validityWindow=%u capped to %us on iOS "
        @"(LATouchIDAuthenticationMaximumAllowableReuseDuration)",
        windowSec, kMaxReuseDurationSec);
    });
    effective = kMaxReuseDurationSec;
  }
  if (effective == 0) {
    // No reuse — fresh context every read so iOS prompts every time.
    LAContext* ctx = [[LAContext alloc] init];
    ctx.touchIDAuthenticationAllowableReuseDuration = 0;
    return ctx;
  }
  @synchronized (laContextCache()) {
    LAContext* ctx = laContextCache()[alias];
    if (ctx == nil) {
      ctx = [[LAContext alloc] init];
      laContextCache()[alias] = ctx;
    }
    // Keep the duration in sync with the stored window — the caller may
    // have re-provisioned with a different window since last cached.
    ctx.touchIDAuthenticationAllowableReuseDuration =
      (NSTimeInterval)effective;
    return ctx;
  }
}

void invalidateContextForAlias(NSString* alias) {
  @synchronized (laContextCache()) {
    [laContextCache() removeObjectForKey:alias];
  }
}

NSString* serviceName() {
  static NSString* cached = nil;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    NSString* bundleId = [[NSBundle mainBundle] bundleIdentifier];
    if (bundleId.length == 0) {
      // Tests / extensions without a real bundle id — keep the namespace
      // explicit rather than letting Keychain default to nil.
      bundleId = @"com.fintoda.reactnativecryptolib.unknown";
    }
    cached = [[NSString alloc] initWithFormat:@"%@.cryptolib.kv", bundleId];
  });
  return cached;
}

NSString* nsString(const std::string& s) {
  return [[NSString alloc] initWithBytes:s.data()
                                  length:s.size()
                                encoding:NSUTF8StringEncoding];
}

NSDictionary* baseQuery(const std::string& key) {
  return @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : serviceName(),
    (__bridge id)kSecAttrAccount : nsString(key),
  };
}

[[noreturn]] void throwOSStatus(const char* op, OSStatus status) {
  throw std::runtime_error(
    std::string(op) + " failed (OSStatus " + std::to_string((long)status) + ")");
}

}  // namespace

void SecureKVBackend::set(
  const std::string& key,
  const uint8_t* data,
  size_t len,
  AccessControl ac,
  uint32_t validityWindowSec,
  uint8_t slotKind,
  const BiometricPromptCopy& prompt
) {
  // The set() path does not show a Keychain prompt itself — provisioning
  // happens without auth on iOS. The `prompt` argument is accepted for
  // API symmetry with Android (where biometric set() *does* prompt) and
  // future iOS variants. Silence the unused-parameter warning.
  (void)prompt;
  NSData* value = [NSData dataWithBytes:data length:len];

  // Overwrite semantics: drop any existing item, then add fresh. We don't
  // use SecItemUpdate because an item created by an older accessibility
  // attribute (e.g. before our default changed) would silently keep that
  // attribute on update — a real footgun if the caller switches a key
  // from 'none' to 'biometric'.
  NSMutableDictionary* delQuery = [baseQuery(key) mutableCopy];
  OSStatus delStatus = SecItemDelete((__bridge CFDictionaryRef)delQuery);
  if (delStatus != errSecSuccess && delStatus != errSecItemNotFound) {
    throwOSStatus("secureKV.set (cleanup)", delStatus);
  }

  // Drop any cached LAContext for this alias — the new item may carry a
  // different window or no biometric flag at all.
  invalidateContextForAlias(nsString(key));

  NSMutableDictionary* add = [baseQuery(key) mutableCopy];
  add[(__bridge id)kSecValueData] = value;

  if (ac == AccessControl::Biometric) {
    // SecAccessControl supersedes kSecAttrAccessible. Use
    // kSecAccessControlBiometryCurrentSet so that a re-enrollment of
    // biometrics (adding/removing a fingerprint or Face ID) invalidates
    // the item — defence against a stolen device whose threat model is
    // "attacker enrolls their own biometrics".
    CFErrorRef cfErr = NULL;
    SecAccessControlRef acRef = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecAccessControlBiometryCurrentSet,
      &cfErr
    );
    if (acRef == NULL) {
      NSError* nsErr = (__bridge_transfer NSError*)cfErr;
      throw std::runtime_error(
        std::string("secureKV.set: SecAccessControlCreate failed: ") +
        [[nsErr description] UTF8String]);
    }
    add[(__bridge id)kSecAttrAccessControl] = (__bridge_transfer id)acRef;
  } else {
    add[(__bridge id)kSecAttrAccessible] =
      (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
  }

  // Plaintext metadata header in kSecAttrGeneric (always 7 bytes):
  //   [4B window BE][1B has_passphrase][1B slot_kind][1B accessControl]
  // Read by metadata() and the get() path without triggering biometric.
  // Window is always written even for non-biometric items (=0) so the
  // attribute size is uniform and parsing is unconditional.
  // accessControl is stored explicitly because Keychain returns a
  // synthetic kSecAttrAccessControl for items added with only
  // kSecAttrAccessible — checking presence of that attribute is
  // therefore not a reliable biometric/non-biometric signal.
  uint8_t hasPp = (slotKind == 0x03) ? 1 : 0;
  uint8_t metaBuf[7] = {
    static_cast<uint8_t>((validityWindowSec >> 24) & 0xff),
    static_cast<uint8_t>((validityWindowSec >> 16) & 0xff),
    static_cast<uint8_t>((validityWindowSec >> 8) & 0xff),
    static_cast<uint8_t>(validityWindowSec & 0xff),
    hasPp,
    slotKind,
    static_cast<uint8_t>(ac),
  };
  add[(__bridge id)kSecAttrGeneric] =
    [NSData dataWithBytes:metaBuf length:7];

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
  if (status != errSecSuccess) {
    throwOSStatus("secureKV.set", status);
  }
}

std::optional<std::vector<uint8_t>> SecureKVBackend::get(
  const std::string& key,
  const BiometricPromptCopy& prompt
) {
  // First pass: fetch attributes only. Attribute reads do NOT trigger
  // the biometric prompt; only data reads do. This lets us detect a
  // biometric-protected item and pull the validity window out of
  // kSecAttrGeneric before deciding whether (and with what LAContext)
  // to ask for the data.
  NSMutableDictionary* attrQuery = [baseQuery(key) mutableCopy];
  attrQuery[(__bridge id)kSecReturnAttributes] = @YES;
  attrQuery[(__bridge id)kSecReturnData] = @NO;
  attrQuery[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  // Suppress any UI on this lookup so we get a clean errSecInteractionNotAllowed
  // rather than a stray prompt if the item happens to require it.
  attrQuery[(__bridge id)kSecUseAuthenticationUI] =
    (__bridge id)kSecUseAuthenticationUISkip;

  CFTypeRef cfAttrs = NULL;
  OSStatus attrStatus =
    SecItemCopyMatching((__bridge CFDictionaryRef)attrQuery, &cfAttrs);
  if (attrStatus == errSecItemNotFound) {
    return std::nullopt;
  }
  if (attrStatus != errSecSuccess) {
    throwOSStatus("secureKV.get (attrs)", attrStatus);
  }
  NSDictionary* attrs = (__bridge_transfer NSDictionary*)cfAttrs;
  NSData* metaAttr = attrs[(__bridge id)kSecAttrGeneric];
  // Read accessControl from the explicit byte at offset 6 in our
  // metadata blob. Falling back to checking `kSecAttrAccessControl`
  // presence is unreliable — Keychain synthesises that attribute for
  // items added with only `kSecAttrAccessible`, so the presence test
  // returns true even for non-biometric items.
  bool isBiometric = false;
  if (metaAttr != nil && metaAttr.length >= 7) {
    const uint8_t* mb = static_cast<const uint8_t*>(metaAttr.bytes);
    isBiometric = mb[6] != 0;
  }

  NSMutableDictionary* dataQuery = [baseQuery(key) mutableCopy];
  dataQuery[(__bridge id)kSecReturnData] = @YES;
  dataQuery[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

  if (isBiometric) {
    // Biometric item — decode window from the 4 BE bytes (first half of
    // the meta attribute), attach a (possibly cached) LAContext so iOS
    // can skip the prompt within the reuse window.
    uint32_t windowSec = 0;
    if (metaAttr != nil && metaAttr.length >= 4) {
      const uint8_t* wb = static_cast<const uint8_t*>(metaAttr.bytes);
      windowSec =
        (static_cast<uint32_t>(wb[0]) << 24) |
        (static_cast<uint32_t>(wb[1]) << 16) |
        (static_cast<uint32_t>(wb[2]) << 8) |
        static_cast<uint32_t>(wb[3]);
    }
    LAContext* ctx = contextForRead(nsString(key), windowSec);
    dataQuery[(__bridge id)kSecUseAuthenticationContext] = ctx;
    // iOS surfaces a single user-visible message in the Keychain
    // prompt. Prefer subtitle (the equivalent of LAContext.localizedReason
    // in the standalone biometric API), fall back to title; if both
    // empty, omit the override and the system default applies.
    NSString* reason = nil;
    if (!prompt.subtitle.empty()) reason = nsString(prompt.subtitle);
    else if (!prompt.title.empty()) reason = nsString(prompt.title);
    if (reason != nil) {
      dataQuery[(__bridge id)kSecUseOperationPrompt] = reason;
    }
    if (!prompt.cancelLabel.empty()) {
      ctx.localizedCancelTitle = nsString(prompt.cancelLabel);
    }
  }

  CFTypeRef cfResult = NULL;
  OSStatus status =
    SecItemCopyMatching((__bridge CFDictionaryRef)dataQuery, &cfResult);
  if (status == errSecItemNotFound) {
    return std::nullopt;
  }
  if (status != errSecSuccess) {
    // -128 / errSecUserCanceled — surface verbatim so the JS layer can
    // detect the cancel via the OSStatus number.
    throwOSStatus("secureKV.get", status);
  }

  NSData* data = (__bridge_transfer NSData*)cfResult;
  const uint8_t* bytes = static_cast<const uint8_t*>(data.bytes);
  return std::vector<uint8_t>(bytes, bytes + data.length);
}

bool SecureKVBackend::has(const std::string& key) {
  NSMutableDictionary* query = [baseQuery(key) mutableCopy];
  query[(__bridge id)kSecReturnData] = @NO;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  // Suppress UI explicitly. Without this, biometric items can in theory
  // trigger an authentication prompt during a `has()` lookup. With UISkip,
  // a biometric item returns errSecInteractionNotAllowed, which we map to
  // "exists" — has() must never block on user input.
  query[(__bridge id)kSecUseAuthenticationUI] =
    (__bridge id)kSecUseAuthenticationUISkip;

  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
  if (status == errSecSuccess) return true;
  if (status == errSecItemNotFound) return false;
  if (status == errSecInteractionNotAllowed) return true;
  throwOSStatus("secureKV.has", status);
}

void SecureKVBackend::remove(const std::string& key) {
  invalidateContextForAlias(nsString(key));
  OSStatus status =
    SecItemDelete((__bridge CFDictionaryRef)baseQuery(key));
  if (status != errSecSuccess && status != errSecItemNotFound) {
    throwOSStatus("secureKV.delete", status);
  }
}

std::vector<std::string> SecureKVBackend::list() {
  NSDictionary* query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : serviceName(),
    (__bridge id)kSecReturnAttributes : @YES,
    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitAll,
  };

  CFTypeRef cfResult = NULL;
  OSStatus status =
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &cfResult);
  if (status == errSecItemNotFound) return {};
  if (status != errSecSuccess) {
    throwOSStatus("secureKV.list", status);
  }

  NSArray* items = (__bridge_transfer NSArray*)cfResult;
  std::vector<std::string> keys;
  keys.reserve(items.count);
  for (NSDictionary* item in items) {
    NSString* account = item[(__bridge id)kSecAttrAccount];
    if (account == nil) continue;
    keys.emplace_back([account UTF8String]);
  }
  return keys;
}

void SecureKVBackend::clear() {
  @synchronized (laContextCache()) {
    [laContextCache() removeAllObjects];
  }
  NSDictionary* query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : serviceName(),
  };
  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
  if (status != errSecSuccess && status != errSecItemNotFound) {
    throwOSStatus("secureKV.clear", status);
  }
}

BackendItemMetadata SecureKVBackend::metadata(const std::string& key) {
  // Attribute-only Keychain query with kSecUseAuthenticationUISkip — on
  // biometric items this returns the attributes (incl. our 6-byte
  // kSecAttrGeneric blob) without ever showing a prompt. Same path as
  // has() / get()'s first pass.
  NSMutableDictionary* attrQuery = [baseQuery(key) mutableCopy];
  attrQuery[(__bridge id)kSecReturnAttributes] = @YES;
  attrQuery[(__bridge id)kSecReturnData] = @NO;
  attrQuery[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  attrQuery[(__bridge id)kSecUseAuthenticationUI] =
    (__bridge id)kSecUseAuthenticationUISkip;

  CFTypeRef cfAttrs = NULL;
  OSStatus status =
    SecItemCopyMatching((__bridge CFDictionaryRef)attrQuery, &cfAttrs);
  BackendItemMetadata out;
  if (status == errSecItemNotFound) {
    return out;
  }
  if (status == errSecInteractionNotAllowed) {
    // Attribute-only query never needs interaction, so this should not
    // happen in practice. Treat as exists with unknown details rather
    // than throwing — the caller can still issue an auth'd read.
    out.exists = true;
    return out;
  }
  if (status != errSecSuccess) {
    throwOSStatus("secureKV.metadata", status);
  }

  NSDictionary* attrs = (__bridge_transfer NSDictionary*)cfAttrs;
  out.exists = true;
  // Default to None; the explicit accessControl byte in kSecAttrGeneric
  // overrides below. (Don't use `kSecAttrAccessControl` presence —
  // Keychain returns a synthetic value for items added with only
  // kSecAttrAccessible.)
  out.accessControl = AccessControl::None;

  NSData* metaAttr = attrs[(__bridge id)kSecAttrGeneric];
  if (metaAttr != nil) {
    const uint8_t* mb = static_cast<const uint8_t*>(metaAttr.bytes);
    NSUInteger n = metaAttr.length;
    if (n >= 4) {
      out.validityWindowSec =
        (static_cast<uint32_t>(mb[0]) << 24) |
        (static_cast<uint32_t>(mb[1]) << 16) |
        (static_cast<uint32_t>(mb[2]) << 8) |
        static_cast<uint32_t>(mb[3]);
    }
    if (n >= 5) out.hasPassphrase = mb[4] != 0;
    if (n >= 6) out.slotKind = mb[5];
    if (n >= 7) {
      out.accessControl = static_cast<AccessControl>(mb[6]);
    }
  }
  return out;
}

bool SecureKVBackend::isHardwareBacked() {
  // On iOS, every Keychain item with a "ThisDeviceOnly" accessibility class
  // is encrypted with a key tied to the Secure Enclave UID — the value is
  // never stored in plaintext on flash.
  return true;
}

void SecureKVBackend::invalidateSession(const std::string& alias) {
  // Empty alias = invalidate everything. We must call -invalidate on
  // each cached LAContext before dropping it so iOS forgets the
  // outstanding auth, otherwise the auth handle stays live in
  // SecureEnclaved memory until the LAContext is finally dealloc'd.
  @synchronized (laContextCache()) {
    if (alias.empty()) {
      for (NSString* key in laContextCache().allKeys) {
        LAContext* ctx = laContextCache()[key];
        if (ctx != nil) [ctx invalidate];
      }
      [laContextCache() removeAllObjects];
      return;
    }
    NSString* key = nsString(alias);
    LAContext* ctx = laContextCache()[key];
    if (ctx != nil) [ctx invalidate];
    [laContextCache() removeObjectForKey:key];
  }
}

BiometricStatus SecureKVBackend::biometricStatus() {
  LAContext* ctx = [[LAContext alloc] init];
  NSError* err = nil;
  BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                             error:&err];
  if (ok) return BiometricStatus::Available;
  if (err == nil) return BiometricStatus::HardwareUnavailable;
  switch (err.code) {
    case LAErrorBiometryNotEnrolled:
    case LAErrorPasscodeNotSet:
      return BiometricStatus::NotEnrolled;
    case LAErrorBiometryNotAvailable:
      return BiometricStatus::NoHardware;
    case LAErrorBiometryLockout:
      return BiometricStatus::HardwareUnavailable;
    default:
      return BiometricStatus::HardwareUnavailable;
  }
}

}  // namespace facebook::react::cryptolib

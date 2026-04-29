#import <Foundation/Foundation.h>
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
  const std::string& key, const uint8_t* data, size_t len
) {
  NSData* value = [NSData dataWithBytes:data length:len];

  // Overwrite semantics: drop any existing item, then add fresh. We don't
  // use SecItemUpdate because an item created by an older accessibility
  // attribute (e.g. before our default changed) would silently keep that
  // attribute on update.
  NSMutableDictionary* delQuery = [baseQuery(key) mutableCopy];
  OSStatus delStatus = SecItemDelete((__bridge CFDictionaryRef)delQuery);
  if (delStatus != errSecSuccess && delStatus != errSecItemNotFound) {
    throwOSStatus("secureKV.set (cleanup)", delStatus);
  }

  NSMutableDictionary* add = [baseQuery(key) mutableCopy];
  add[(__bridge id)kSecAttrAccessible] =
    (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
  add[(__bridge id)kSecValueData] = value;

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
  if (status != errSecSuccess) {
    throwOSStatus("secureKV.set", status);
  }
}

std::optional<std::vector<uint8_t>> SecureKVBackend::get(
  const std::string& key
) {
  NSMutableDictionary* query = [baseQuery(key) mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

  CFTypeRef cfResult = NULL;
  OSStatus status =
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &cfResult);
  if (status == errSecItemNotFound) {
    return std::nullopt;
  }
  if (status != errSecSuccess) {
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

  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
  if (status == errSecSuccess) return true;
  if (status == errSecItemNotFound) return false;
  throwOSStatus("secureKV.has", status);
}

void SecureKVBackend::remove(const std::string& key) {
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
  NSDictionary* query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : serviceName(),
  };
  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
  if (status != errSecSuccess && status != errSecItemNotFound) {
    throwOSStatus("secureKV.clear", status);
  }
}

bool SecureKVBackend::isHardwareBacked() {
  // On iOS, every Keychain item with a "ThisDeviceOnly" accessibility class
  // is encrypted with a key tied to the Secure Enclave UID — the value is
  // never stored in plaintext on flash.
  return true;
}

}  // namespace facebook::react::cryptolib

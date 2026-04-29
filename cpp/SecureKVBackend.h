#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace facebook::react::cryptolib {

// Per-item access-control gating. Stored alongside the item at provisioning;
// reads inherit it. Future variants will go here without breaking call sites.
enum class AccessControl : uint8_t {
  // No prompt; item is readable while the device is unlocked.
  None = 0,
  // Requires a biometric prompt (Face ID / Touch ID / fingerprint).
  // Pair with a `validityWindow` (seconds) to authorise N seconds of
  // subsequent reads after one prompt; 0 means per-call.
  Biometric = 1,
};

// Biometric availability snapshot. Lets callers query whether
// `accessControl='biometric'` would even work before they try to use it.
// Strings are stable and used directly by the JS-side enum.
enum class BiometricStatus {
  // Biometric is enrolled and ready; provisioning / reads will prompt.
  Available,
  // No biometric hardware on this device (Class 3 / strong).
  NoHardware,
  // Hardware is present but no biometric is enrolled. The user can fix
  // this by going to Settings.
  NotEnrolled,
  // Hardware is temporarily unavailable (sensor failure, lockout).
  HardwareUnavailable,
  // Android only: device requires a security update before biometric
  // operations are allowed.
  SecurityUpdateRequired,
  // Android API < 28; iOS too old for LAPolicy. The library declines
  // biometric on these devices regardless of hardware.
  UnsupportedOs,
};

// Platform-agnostic interface to a hardware-backed key/value store.
//
// The iOS implementation (ios/SecureKVBackend.mm) wraps Security.framework
// (kSecClassGenericPassword, kSecAttrAccessibleWhenUnlockedThisDeviceOnly).
// The Android implementation (android/src/main/cpp/SecureKVBackend_android.cpp)
// wraps SecureKVBridge.kt → AndroidKeystore AES-GCM + file blobs.
//
// Throws std::runtime_error on backend errors (with a short reason). Returns
// std::nullopt from get() / false from has() when the key is absent.
//
// All implementations validate nothing about the key string itself — the
// JSI thunk layer (cpp/SecureKV.cpp) is responsible for charset / length /
// size limits before calling these.
class SecureKVBackend {
 public:
  static void set(
    const std::string& key,
    const uint8_t* data,
    size_t len,
    AccessControl ac,
    uint32_t validityWindowSec  // ignored when ac == None
  );
  static std::optional<std::vector<uint8_t>> get(const std::string& key);
  static bool has(const std::string& key);
  static void remove(const std::string& key);
  static std::vector<std::string> list();
  static void clear();
  static bool isHardwareBacked();
  static BiometricStatus biometricStatus();
};

}  // namespace facebook::react::cryptolib

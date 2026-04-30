#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace facebook::react::cryptolib {

// Caller-supplied biometric prompt copy. Populated by the JSI thunk
// from the JS-level `BiometricPromptOptions` and forwarded to the
// platform backend. Empty strings mean "use platform default" — the
// backend never echoes them verbatim, so callers can pass `{}` to keep
// the system-default prompt UX.
struct BiometricPromptCopy {
  std::string title;
  std::string subtitle;
  std::string cancelLabel;

  bool empty() const noexcept {
    return title.empty() && subtitle.empty() && cancelLabel.empty();
  }
};

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

// Plaintext metadata for an item. Returned by `metadata()` without any
// auth or biometric prompt — populated from header bytes that sit
// outside the encrypted payload (Android: blob header; iOS: kSecAttrGeneric).
struct BackendItemMetadata {
  bool exists = false;
  AccessControl accessControl = AccessControl::None;
  uint32_t validityWindowSec = 0;
  bool hasPassphrase = false;
  // Outer slot tag (the first byte of slot bytes). 0x00=BLOB, 0x01=SEED,
  // 0x02=RAW, 0x03=WRAPPED. When wrapped, the inner kind is hidden
  // behind the passphrase by design.
  uint8_t slotKind = 0;
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
  // `slotKind` is the outer slot tag of the bytes being stored. Surfaced
  // in plaintext metadata so `metadata()` can answer queries about the
  // item without auth. Backends store it alongside the blob header
  // (Android) or in `kSecAttrGeneric` (iOS).
  static void set(
    const std::string& key,
    const uint8_t* data,
    size_t len,
    AccessControl ac,
    uint32_t validityWindowSec,  // ignored when ac == None
    uint8_t slotKind,
    const BiometricPromptCopy& prompt = {}
  );
  static std::optional<std::vector<uint8_t>> get(
    const std::string& key,
    const BiometricPromptCopy& prompt = {}
  );
  static bool has(const std::string& key);
  static void remove(const std::string& key);
  static std::vector<std::string> list();
  static void clear();
  static bool isHardwareBacked();
  static BiometricStatus biometricStatus();

  // Plaintext metadata read — no biometric prompt, no AES decrypt.
  // Returns `{ exists = false }` for missing keys.
  static BackendItemMetadata metadata(const std::string& key);

  // Drops any cached biometric authentication for the given alias (or
  // all aliases when `alias` is empty). On iOS this invalidates the
  // per-alias `LAContext` so the next read prompts fresh, ignoring any
  // outstanding `touchIDAuthenticationAllowableReuseDuration` window.
  // On Android this is a no-op — the validity window lives inside
  // AndroidKeystore and cannot be cleared from userland; callers must
  // wait for it to expire or use `validityWindow: 0` for per-call
  // prompts. Documented as no-op in the JS-level JSDoc so cross-
  // platform code can call it unconditionally.
  static void invalidateSession(const std::string& alias);
};

}  // namespace facebook::react::cryptolib

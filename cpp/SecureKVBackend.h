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
  // Requires a biometric prompt (Face ID / Touch ID / fingerprint) on every
  // read. Phase 1 = per-call only; session-window support comes later.
  Biometric = 1,
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
    AccessControl ac
  );
  static std::optional<std::vector<uint8_t>> get(const std::string& key);
  static bool has(const std::string& key);
  static void remove(const std::string& key);
  static std::vector<std::string> list();
  static void clear();
  static bool isHardwareBacked();
};

}  // namespace facebook::react::cryptolib

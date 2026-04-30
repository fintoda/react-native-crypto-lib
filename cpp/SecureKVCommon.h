#pragma once

#include "Common.h"
#include "SecureKVBackend.h"

#include <cstdint>
#include <string>

// Shared helpers between cpp/SecureKV.cpp (blob slot ops) and
// cpp/SecureKVSign.cpp (BIP-32 / raw signing). Both files validate the
// same key-name charset, parse the same `accessControl` strings, and
// rethrow backend errors the same way; previously each file kept its
// own copy.

namespace facebook::react::cryptolib {

constexpr size_t kMaxKeyLen = 128;

// Restricts key names to a portable charset. iOS Keychain stores them
// as kSecAttrAccount (UTF-8); Android hashes them into filenames.
// Allowing arbitrary user input invites collisions, encoding surprises,
// and path-traversal-style bugs.
inline bool isValidKeyChar(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

inline void requireValidKey(
  jsi::Runtime& rt, const char* op, const std::string& key
) {
  if (key.empty() || key.size() > kMaxKeyLen) {
    throw jsi::JSError(rt, std::string(op) + ": key length out of range");
  }
  for (char c : key) {
    if (!isValidKeyChar(c)) {
      throw jsi::JSError(
        rt, std::string(op) + ": key contains invalid character");
    }
  }
}

[[noreturn]] inline void rethrowAsJsi(
  jsi::Runtime& rt, const char* op, const std::exception& e
) {
  throw jsi::JSError(rt, std::string(op) + ": " + e.what());
}

// Forward-compatible: unknown values are rejected here rather than
// silently ignored so future variants (e.g. 'biometric_or_passcode')
// can be added without breaking call sites.
inline AccessControl parseAccessControl(
  jsi::Runtime& rt, const char* op, const std::string& s
) {
  if (s == "none") return AccessControl::None;
  if (s == "biometric") return AccessControl::Biometric;
  throw jsi::JSError(
    rt, std::string(op) + ": unknown accessControl '" + s + "'");
}

// Reads three optional trailing string args (title, subtitle,
// cancelLabel) into a BiometricPromptCopy. Treats a missing argument
// (count <= index), undefined, or null as empty string — that's the
// shape the JS wrapper produces for `BiometricPromptOptions = undefined`.
inline BiometricPromptCopy parsePromptCopy(
  jsi::Runtime& rt,
  const char* op,
  const jsi::Value* args,
  size_t count,
  size_t titleIndex
) {
  auto readOpt = [&](size_t i, const char* fieldName) -> std::string {
    if (count <= i) return {};
    if (args[i].isUndefined() || args[i].isNull()) return {};
    if (!args[i].isString()) {
      throw jsi::JSError(
        rt, std::string(op) + ": " + fieldName + " must be a string");
    }
    return args[i].getString(rt).utf8(rt);
  };
  BiometricPromptCopy out;
  out.title = readOpt(titleIndex, "promptTitle");
  out.subtitle = readOpt(titleIndex + 1, "promptSubtitle");
  out.cancelLabel = readOpt(titleIndex + 2, "promptCancel");
  return out;
}

// Optional passphrase string. Missing arg, undefined, null, or empty
// string all mean "no passphrase". Non-string values throw. The empty
// distinction lives in the caller — set/get distinguish "no passphrase
// requested" (item is plaintext slot) from "passphrase wrap required".
inline std::string parsePassphrase(
  jsi::Runtime& rt,
  const char* op,
  const jsi::Value* args,
  size_t count,
  size_t index
) {
  if (count <= index) return {};
  if (args[index].isUndefined() || args[index].isNull()) return {};
  if (!args[index].isString()) {
    throw jsi::JSError(rt, std::string(op) + ": passphrase must be a string");
  }
  return args[index].getString(rt).utf8(rt);
}

// Optional passphrase iteration count. Missing / undefined / 0 means
// "use default". Range is [100k, 10M] mirroring SecureKVPassphrase.h
// constants; out-of-range throws so callers don't silently get a
// weaker derivation than asked for.
inline uint32_t parsePassphraseIters(
  jsi::Runtime& rt,
  const char* op,
  const jsi::Value* args,
  size_t count,
  size_t index,
  uint32_t defaultIters
) {
  if (count <= index) return defaultIters;
  if (args[index].isUndefined() || args[index].isNull()) return defaultIters;
  if (!args[index].isNumber()) {
    throw jsi::JSError(
      rt, std::string(op) + ": passphraseIterations must be a number");
  }
  double v = args[index].asNumber();
  if (v == 0) return defaultIters;
  if (v != static_cast<double>(static_cast<uint32_t>(v))) {
    throw jsi::JSError(
      rt, std::string(op) + ": passphraseIterations must be an integer");
  }
  uint32_t iters = static_cast<uint32_t>(v);
  if (iters < 100'000 || iters > 10'000'000) {
    throw jsi::JSError(
      rt, std::string(op) +
      ": passphraseIterations out of range [100000, 10000000]");
  }
  return iters;
}

inline uint32_t parseValidityWindow(
  jsi::Runtime& rt,
  const char* op,
  const jsi::Value* args,
  size_t count,
  size_t index
) {
  if (count <= index) return 0;
  if (args[index].isUndefined() || args[index].isNull()) return 0;
  if (!args[index].isNumber()) {
    throw jsi::JSError(
      rt, std::string(op) + ": validityWindow must be a number");
  }
  double v = args[index].asNumber();
  if (v < 0 || v > static_cast<double>(UINT32_MAX) ||
      v != static_cast<double>(static_cast<uint32_t>(v))) {
    throw jsi::JSError(
      rt, std::string(op) + ": validityWindow must be a non-negative integer");
  }
  return static_cast<uint32_t>(v);
}

}  // namespace facebook::react::cryptolib

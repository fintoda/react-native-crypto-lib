#include "Common.h"
#include "SecureKVBackend.h"
#include "SecureKVSlot.h"

extern "C" {
#include "memzero.h"
}

#include <stdexcept>
#include <string>
#include <vector>

namespace facebook::react::cryptolib {
namespace {

constexpr size_t kMaxKeyLen = 128;
constexpr size_t kMaxValueLen = 65536;  // 64 KiB

// Restrict key names to a portable charset. iOS Keychain stores them as
// kSecAttrAccount (UTF-8); on Android we hash them into filenames. Allowing
// arbitrary user input invites collisions, encoding surprises, and
// path-traversal-style bugs.
bool isValidKeyChar(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

[[noreturn]] void wrap(jsi::Runtime& rt, const char* op, const std::exception& e) {
  throw jsi::JSError(rt, std::string(op) + ": " + e.what());
}

// Parses the JS-side accessControl string. Phase 1 accepts 'none' and
// 'biometric'; the schema is forward-compatible with future variants
// (e.g. 'biometric_or_passcode') because unknown values are rejected
// here rather than silently ignored.
AccessControl parseAccessControl(
  jsi::Runtime& rt, const char* op, const std::string& s
) {
  if (s == "none") return AccessControl::None;
  if (s == "biometric") return AccessControl::Biometric;
  throw jsi::JSError(
    rt, std::string(op) + ": unknown accessControl '" + s + "'");
}

void requireValidKey(jsi::Runtime& rt, const char* op, const std::string& key) {
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

jsi::Value invoke_set(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return makePromise(rt, [args, count](jsi::Runtime& rt) -> jsi::Value {
    std::string key = requireStringAt(rt, "secure_kv_set", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_set", key);
    auto value = requireArrayBufferAt(rt, "secure_kv_set", "value", args, count, 1);
    size_t len = value.size(rt);
    if (len > kMaxValueLen) {
      throw jsi::JSError(rt, "secure_kv_set: value exceeds 64 KiB limit");
    }
    std::string acStr =
      requireStringAt(rt, "secure_kv_set", "accessControl", args, count, 2);
    AccessControl ac = parseAccessControl(rt, "secure_kv_set", acStr);
    auto wrapped = wrapBlobSlot(safeData(rt, value), len);
    try {
      SecureKVBackend::set(key, wrapped.data(), wrapped.size(), ac);
    } catch (const std::exception& e) {
      memzero(wrapped.data(), wrapped.size());
      wrap(rt, "secure_kv_set", e);
    }
    memzero(wrapped.data(), wrapped.size());
    return jsi::Value::undefined();
  });
}

jsi::Value invoke_get(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return makePromise(rt, [args, count](jsi::Runtime& rt) -> jsi::Value {
    std::string key = requireStringAt(rt, "secure_kv_get", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_get", key);
    std::optional<std::vector<uint8_t>> result;
    try {
      result = SecureKVBackend::get(key);
    } catch (const std::exception& e) {
      wrap(rt, "secure_kv_get", e);
    }
    if (!result.has_value()) {
      return jsi::Value::null();
    }
    SlotView slot;
    if (!parseSlot(result->data(), result->size(), slot) ||
        slot.kind != SlotKind::Blob) {
      memzero(result->data(), result->size());
      throw jsi::JSError(
        rt,
        std::string("secure_kv_get: slot is ") + slotKindName(slot.kind) +
          ", expected BLOB"
      );
    }
    std::vector<uint8_t> out(slot.payload, slot.payload + slot.payloadLen);
    memzero(result->data(), result->size());
    return wrapDigest(rt, std::move(out));
  });
}

jsi::Value invoke_has(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return makePromise(rt, [args, count](jsi::Runtime& rt) -> jsi::Value {
    std::string key = requireStringAt(rt, "secure_kv_has", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_has", key);
    try {
      return jsi::Value(SecureKVBackend::has(key));
    } catch (const std::exception& e) {
      wrap(rt, "secure_kv_has", e);
    }
  });
}

jsi::Value invoke_delete(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return makePromise(rt, [args, count](jsi::Runtime& rt) -> jsi::Value {
    std::string key =
      requireStringAt(rt, "secure_kv_delete", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_delete", key);
    try {
      SecureKVBackend::remove(key);
    } catch (const std::exception& e) {
      wrap(rt, "secure_kv_delete", e);
    }
    return jsi::Value::undefined();
  });
}

jsi::Value invoke_list(
  jsi::Runtime& rt, TurboModule&, const jsi::Value*, size_t
) {
  return makePromise(rt, [](jsi::Runtime& rt) -> jsi::Value {
    std::vector<std::string> keys;
    try {
      keys = SecureKVBackend::list();
    } catch (const std::exception& e) {
      wrap(rt, "secure_kv_list", e);
    }
    jsi::Array out(rt, keys.size());
    for (size_t i = 0; i < keys.size(); ++i) {
      out.setValueAtIndex(rt, i, jsi::String::createFromUtf8(rt, keys[i]));
    }
    return out;
  });
}

jsi::Value invoke_clear(
  jsi::Runtime& rt, TurboModule&, const jsi::Value*, size_t
) {
  return makePromise(rt, [](jsi::Runtime& rt) -> jsi::Value {
    try {
      SecureKVBackend::clear();
    } catch (const std::exception& e) {
      wrap(rt, "secure_kv_clear", e);
    }
    return jsi::Value::undefined();
  });
}

jsi::Value invoke_is_hardware_backed(
  jsi::Runtime& rt, TurboModule&, const jsi::Value*, size_t
) {
  return makePromise(rt, [](jsi::Runtime& rt) -> jsi::Value {
    try {
      return jsi::Value(SecureKVBackend::isHardwareBacked());
    } catch (const std::exception& e) {
      wrap(rt, "secure_kv_is_hardware_backed", e);
    }
  });
}

}  // namespace

void registerSecureKVMethods(MethodMap& map) {
  map.push_back({"secure_kv_set",                3, invoke_set});
  map.push_back({"secure_kv_get",                1, invoke_get});
  map.push_back({"secure_kv_has",                1, invoke_has});
  map.push_back({"secure_kv_delete",             1, invoke_delete});
  map.push_back({"secure_kv_list",               0, invoke_list});
  map.push_back({"secure_kv_clear",              0, invoke_clear});
  map.push_back({"secure_kv_is_hardware_backed", 0, invoke_is_hardware_backed});
}

}  // namespace facebook::react::cryptolib

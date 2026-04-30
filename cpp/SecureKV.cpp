#include "Common.h"
#include "SecureKVBackend.h"
#include "SecureKVCommon.h"
#include "SecureKVPassphrase.h"
#include "SecureKVSlot.h"

extern "C" {
#include "memzero.h"
}

#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// SecureKV JSI thunks. Every public method goes through makePromiseAsync
// (cpp/Common.h): args are validated synchronously on the JS thread,
// the platform backend call runs on a worker thread, and a finishWork
// continuation runs back on the JS thread to wrap the result in a
// jsi::Value. This keeps the JS thread responsive while a Keychain
// lookup or biometric prompt is in flight.
//
// Each thunk wraps its body in safeAsyncThunk(rt, ...) so synchronous
// jsi::JSError throws from Phase 1 (validation) surface as Promise
// rejections — without it, callers using `.catch()` instead of
// `try/await` would miss validation errors.

namespace facebook::react::cryptolib {
namespace {

constexpr size_t kMaxValueLen = 65536;  // 64 KiB

const char* biometricStatusName(BiometricStatus s) {
  switch (s) {
    case BiometricStatus::Available: return "available";
    case BiometricStatus::NoHardware: return "no_hardware";
    case BiometricStatus::NotEnrolled: return "not_enrolled";
    case BiometricStatus::HardwareUnavailable: return "hardware_unavailable";
    case BiometricStatus::SecurityUpdateRequired: return "security_update_required";
    case BiometricStatus::UnsupportedOs: return "unsupported_os";
  }
  return "hardware_unavailable";
}

// --- set ----------------------------------------------------------------

jsi::Value invoke_set(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    std::string key = requireStringAt(rt, "secure_kv_set", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_set", key);
    auto value = requireArrayBufferAt(rt, "secure_kv_set", "value", args, count, 1);
    size_t len = value.size(rt);
    if (len > kMaxValueLen) {
      throw jsi::JSError(rt, "secure_kv_set: value exceeds 64 KiB limit");
    }
    std::string acStr = requireStringAt(rt, "secure_kv_set", "accessControl", args, count, 2);
    AccessControl ac = parseAccessControl(rt, "secure_kv_set", acStr);
    uint32_t window = parseValidityWindow(rt, "secure_kv_set", args, count, 3);
    BiometricPromptCopy prompt = parsePromptCopy(rt, "secure_kv_set", args, count, 4);
    std::string passphrase = parsePassphrase(rt, "secure_kv_set", args, count, 7);
    uint32_t iters = parsePassphraseIters(
      rt, "secure_kv_set", args, count, 8, kKdfDefaultIters);

    // Wrap into a BLOB slot first. If a passphrase was supplied, run
    // wrapPassphraseEnvelope on top — the resulting bytes are themselves
    // a valid PassphraseWrapped slot ([0x03][header][cipher]). Storage
    // sees the outer slot byte and saves it as `slotKind` for metadata.
    std::vector<uint8_t> innerSlot = wrapBlobSlot(safeData(rt, value), len);
    std::vector<uint8_t> stored;
    uint8_t slotKind;
    if (passphrase.empty()) {
      stored = std::move(innerSlot);
      slotKind = static_cast<uint8_t>(SlotKind::Blob);
    } else {
      try {
        stored = wrapPassphraseEnvelope(
          innerSlot.data(), innerSlot.size(), passphrase, iters);
      } catch (...) {
        memzero(innerSlot.data(), innerSlot.size());
        throw;
      }
      memzero(innerSlot.data(), innerSlot.size());
      slotKind = static_cast<uint8_t>(SlotKind::PassphraseWrapped);
    }

    return makePromiseAsync<bool>(
      rt, "secure_kv_set",
      [key = std::move(key), stored = std::move(stored), ac, window, slotKind,
       prompt = std::move(prompt)]() mutable -> bool {
        try {
          SecureKVBackend::set(
            key, stored.data(), stored.size(), ac, window, slotKind, prompt);
        } catch (...) {
          memzero(stored.data(), stored.size());
          throw;
        }
        memzero(stored.data(), stored.size());
        return true;
      },
      [](jsi::Runtime&, bool&&) -> jsi::Value {
        return jsi::Value::undefined();
      }
    );
  });
}

// --- get ----------------------------------------------------------------

jsi::Value invoke_get(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    std::string key = requireStringAt(rt, "secure_kv_get", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_get", key);
    BiometricPromptCopy prompt = parsePromptCopy(rt, "secure_kv_get", args, count, 1);
    std::string passphrase = parsePassphrase(rt, "secure_kv_get", args, count, 4);

    // BgResult: optional<vector> for null-on-missing-key, plus we already
    // unwrap the slot here so finishWork stays trivial. Passphrase-wrapped
    // items get unwrapped on the bg thread before slot kind enforcement.
    return makePromiseAsync<std::optional<std::vector<uint8_t>>>(
      rt, "secure_kv_get",
      [key = std::move(key), prompt = std::move(prompt),
       passphrase = std::move(passphrase)]()
          -> std::optional<std::vector<uint8_t>> {
        auto raw = SecureKVBackend::get(key, prompt);
        if (!raw.has_value()) return std::nullopt;
        SlotView slot;
        if (!parseSlot(raw->data(), raw->size(), slot)) {
          memzero(raw->data(), raw->size());
          throw std::runtime_error("slot empty");
        }
        // PassphraseWrapped → unwrap inline, replace `raw` with inner
        // slot bytes, then re-parse.
        std::vector<uint8_t> innerStorage;
        if (slot.kind == SlotKind::PassphraseWrapped) {
          if (passphrase.empty()) {
            memzero(raw->data(), raw->size());
            throw std::runtime_error("passphrase: required");
          }
          try {
            innerStorage = unwrapPassphraseEnvelope(
              raw->data(), raw->size(), passphrase);
          } catch (...) {
            memzero(raw->data(), raw->size());
            throw;
          }
          memzero(raw->data(), raw->size());
          if (!parseSlot(innerStorage.data(), innerStorage.size(), slot)) {
            memzero(innerStorage.data(), innerStorage.size());
            throw std::runtime_error("slot empty after unwrap");
          }
        }
        if (slot.kind != SlotKind::Blob) {
          std::string kind = slotKindName(slot.kind);
          if (!innerStorage.empty()) {
            memzero(innerStorage.data(), innerStorage.size());
          } else {
            memzero(raw->data(), raw->size());
          }
          throw std::runtime_error("slot is " + kind + ", expected BLOB");
        }
        std::vector<uint8_t> out(slot.payload, slot.payload + slot.payloadLen);
        if (!innerStorage.empty()) {
          memzero(innerStorage.data(), innerStorage.size());
        } else {
          memzero(raw->data(), raw->size());
        }
        return out;
      },
      [](jsi::Runtime& rt, std::optional<std::vector<uint8_t>>&& bgResult)
          -> jsi::Value {
        if (!bgResult.has_value()) return jsi::Value::null();
        return wrapDigest(rt, std::move(*bgResult));
      }
    );
  });
}

// --- has ----------------------------------------------------------------

jsi::Value invoke_has(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    std::string key = requireStringAt(rt, "secure_kv_has", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_has", key);

    return makePromiseAsync<bool>(
      rt, "secure_kv_has",
      [key = std::move(key)]() -> bool {
        return SecureKVBackend::has(key);
      },
      [](jsi::Runtime&, bool&& v) -> jsi::Value {
        return jsi::Value(v);
      }
    );
  });
}

// --- delete -------------------------------------------------------------

jsi::Value invoke_delete(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    std::string key = requireStringAt(rt, "secure_kv_delete", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_delete", key);

    return makePromiseAsync<bool>(
      rt, "secure_kv_delete",
      [key = std::move(key)]() -> bool {
        SecureKVBackend::remove(key);
        return true;
      },
      [](jsi::Runtime&, bool&&) -> jsi::Value {
        return jsi::Value::undefined();
      }
    );
  });
}

// --- list ---------------------------------------------------------------

jsi::Value invoke_list(
  jsi::Runtime& rt, TurboModule&, const jsi::Value*, size_t
) {
  return safeAsyncThunk(rt, [&] {
    return makePromiseAsync<std::vector<std::string>>(
      rt, "secure_kv_list",
      []() -> std::vector<std::string> {
        return SecureKVBackend::list();
      },
      [](jsi::Runtime& rt, std::vector<std::string>&& keys) -> jsi::Value {
        jsi::Array out(rt, keys.size());
        for (size_t i = 0; i < keys.size(); ++i) {
          out.setValueAtIndex(rt, i, jsi::String::createFromUtf8(rt, keys[i]));
        }
        return out;
      }
    );
  });
}

// --- clear --------------------------------------------------------------

jsi::Value invoke_clear(
  jsi::Runtime& rt, TurboModule&, const jsi::Value*, size_t
) {
  return safeAsyncThunk(rt, [&] {
    return makePromiseAsync<bool>(
      rt, "secure_kv_clear",
      []() -> bool {
        SecureKVBackend::clear();
        return true;
      },
      [](jsi::Runtime&, bool&&) -> jsi::Value {
        return jsi::Value::undefined();
      }
    );
  });
}

// --- isHardwareBacked ---------------------------------------------------

jsi::Value invoke_is_hardware_backed(
  jsi::Runtime& rt, TurboModule&, const jsi::Value*, size_t
) {
  return safeAsyncThunk(rt, [&] {
    return makePromiseAsync<bool>(
      rt, "secure_kv_is_hardware_backed",
      []() -> bool {
        return SecureKVBackend::isHardwareBacked();
      },
      [](jsi::Runtime&, bool&& v) -> jsi::Value {
        return jsi::Value(v);
      }
    );
  });
}

// --- biometricStatus ---------------------------------------------------

jsi::Value invoke_biometric_status(
  jsi::Runtime& rt, TurboModule&, const jsi::Value*, size_t
) {
  return safeAsyncThunk(rt, [&] {
    return makePromiseAsync<BiometricStatus>(
      rt, "secure_kv_biometric_status",
      []() -> BiometricStatus {
        return SecureKVBackend::biometricStatus();
      },
      [](jsi::Runtime& rt, BiometricStatus&& s) -> jsi::Value {
        return jsi::String::createFromUtf8(rt, biometricStatusName(s));
      }
    );
  });
}

// --- metadata -----------------------------------------------------------

const char* slotKindHumanName(uint8_t k) {
  switch (k) {
    case 0x00: return "BLOB";
    case 0x01: return "SEED";
    case 0x02: return "RAW";
    case 0x03: return "WRAPPED";
    default: return "UNKNOWN";
  }
}

jsi::Value invoke_metadata(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    std::string key = requireStringAt(
      rt, "secure_kv_metadata", "key", args, count, 0);
    requireValidKey(rt, "secure_kv_metadata", key);

    return makePromiseAsync<BackendItemMetadata>(
      rt, "secure_kv_metadata",
      [key = std::move(key)]() -> BackendItemMetadata {
        return SecureKVBackend::metadata(key);
      },
      [](jsi::Runtime& rt, BackendItemMetadata&& m) -> jsi::Value {
        jsi::Object out(rt);
        out.setProperty(rt, "exists", jsi::Value(m.exists));
        if (!m.exists) return out;
        out.setProperty(rt, "accessControl",
          jsi::String::createFromUtf8(
            rt, m.accessControl == AccessControl::Biometric
              ? "biometric" : "none"));
        out.setProperty(rt, "validityWindow",
          jsi::Value(static_cast<double>(m.validityWindowSec)));
        out.setProperty(rt, "hasPassphrase", jsi::Value(m.hasPassphrase));
        out.setProperty(rt, "slotKind",
          jsi::String::createFromUtf8(rt, slotKindHumanName(m.slotKind)));
        return out;
      }
    );
  });
}

// --- invalidateSession --------------------------------------------------

jsi::Value invoke_invalidate_session(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    // Empty string = invalidate every cached alias. JS validates length
    // and charset only when an alias was provided, so we don't enforce
    // requireValidKey on the empty input.
    std::string alias = requireStringAt(
      rt, "secure_kv_invalidate_session", "alias", args, count, 0);
    if (!alias.empty()) {
      requireValidKey(rt, "secure_kv_invalidate_session", alias);
    }

    return makePromiseAsync<bool>(
      rt, "secure_kv_invalidate_session",
      [alias = std::move(alias)]() -> bool {
        SecureKVBackend::invalidateSession(alias);
        return true;
      },
      [](jsi::Runtime&, bool&&) -> jsi::Value {
        return jsi::Value::undefined();
      }
    );
  });
}

}  // namespace

void registerSecureKVMethods(MethodMap& map) {
  // set: key, value, accessControl, window, promptT, promptS, promptC,
  //      passphrase, passphraseIters
  map.push_back({"secure_kv_set",                 9, invoke_set});
  // get: key, promptT, promptS, promptC, passphrase
  map.push_back({"secure_kv_get",                 5, invoke_get});
  map.push_back({"secure_kv_has",                 1, invoke_has});
  map.push_back({"secure_kv_delete",              1, invoke_delete});
  map.push_back({"secure_kv_list",                0, invoke_list});
  map.push_back({"secure_kv_clear",               0, invoke_clear});
  map.push_back({"secure_kv_is_hardware_backed",  0, invoke_is_hardware_backed});
  map.push_back({"secure_kv_biometric_status",    0, invoke_biometric_status});
  map.push_back({"secure_kv_metadata",            1, invoke_metadata});
  map.push_back({"secure_kv_invalidate_session",  1, invoke_invalidate_session});
}

}  // namespace facebook::react::cryptolib

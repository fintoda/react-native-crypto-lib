// SecureKV passphrase rotation, access-control change, and seed
// export/import thunks. All four use the wrap/unwrap helpers from
// cpp/SecureKVPassphrase.{h,cpp} so the envelope format is identical
// across in-storage protection and standalone backup blobs.
//
// All bodies run on a worker thread via makePromiseAsync — they call
// backend.get / backend.set which can block on a biometric prompt.
// Slot bytes (raw seed material when unwrapped) never leave the worker
// thread and are zeroed on every code path including throws.

#include "Common.h"
#include "SecureKVBackend.h"
#include "SecureKVCommon.h"
#include "SecureKVPassphrase.h"
#include "SecureKVSlot.h"

extern "C" {
#include "memzero.h"
}

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace facebook::react::cryptolib {
namespace {

// Pulls the access-control + slot kind for an existing item without
// requiring auth. Throws if the item is missing — set/changePassphrase
// callers expect to be operating on something that's already there.
BackendItemMetadata requireMetadata(const std::string& key, const char* op) {
  auto m = SecureKVBackend::metadata(key);
  if (!m.exists) {
    throw std::runtime_error(std::string(op) + ": key not found");
  }
  return m;
}

// Returns inner slot bytes from a (possibly wrapped) outer blob. If
// outer is PassphraseWrapped, requires `passphrase` and unwraps. If
// outer is not wrapped, returns it unchanged. Caller owns the result
// and must memzero before discard.
std::vector<uint8_t> unwrapToInner(
  std::vector<uint8_t>&& outer,
  const std::string& passphrase
) {
  if (outer.empty()) {
    throw std::runtime_error("backup: stored blob empty");
  }
  if (outer[0] == static_cast<uint8_t>(SlotKind::PassphraseWrapped)) {
    if (passphrase.empty()) {
      memzero(outer.data(), outer.size());
      throw std::runtime_error("passphrase: required");
    }
    auto inner = unwrapPassphraseEnvelope(
      outer.data(), outer.size(), passphrase);
    memzero(outer.data(), outer.size());
    return inner;
  }
  return std::move(outer);
}

// --- changePassphrase ----------------------------------------------------

jsi::Value invoke_change_passphrase(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_change_passphrase";
    std::string key = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, key);
    std::string oldPp = parsePassphrase(rt, op, args, count, 1);
    std::string newPp = parsePassphrase(rt, op, args, count, 2);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 3);
    uint32_t newIters =
      parsePassphraseIters(rt, op, args, count, 6, kKdfDefaultIters);

    return makePromiseAsync<bool>(
      rt, op,
      [key = std::move(key), oldPp = std::move(oldPp),
       newPp = std::move(newPp), newIters,
       prompt = std::move(prompt)]() mutable -> bool {
        // Read existing access-control + window so we can re-write
        // under the same gating. metadata() does not prompt.
        auto md = requireMetadata(key, "secure_kv_change_passphrase");

        auto raw = SecureKVBackend::get(key, prompt);
        if (!raw.has_value()) {
          throw std::runtime_error(
            "secure_kv_change_passphrase: key not found");
        }
        std::vector<uint8_t> inner = unwrapToInner(std::move(*raw), oldPp);

        // inner is now the bare slot bytes (Blob/Seed/Raw) regardless
        // of whether the original item was wrapped. Now (optionally)
        // re-wrap under newPp.
        std::vector<uint8_t> stored;
        uint8_t newSlotKind;
        if (newPp.empty()) {
          // No new wrap — the inner slot byte IS what the storage
          // layer should record as the outer slot kind.
          newSlotKind = inner.empty()
            ? static_cast<uint8_t>(SlotKind::Blob)
            : inner[0];
          stored = std::move(inner);
        } else {
          try {
            stored = wrapPassphraseEnvelope(
              inner.data(), inner.size(), newPp, newIters);
          } catch (...) {
            memzero(inner.data(), inner.size());
            throw;
          }
          memzero(inner.data(), inner.size());
          newSlotKind = static_cast<uint8_t>(SlotKind::PassphraseWrapped);
        }

        try {
          SecureKVBackend::set(
            key, stored.data(), stored.size(),
            md.accessControl, md.validityWindowSec, newSlotKind, prompt);
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

// --- changeAccessControl -------------------------------------------------

jsi::Value invoke_change_access_control(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_change_access_control";
    std::string key = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, key);
    std::string acStr =
      requireStringAt(rt, op, "accessControl", args, count, 1);
    AccessControl newAc = parseAccessControl(rt, op, acStr);
    uint32_t newWindow = parseValidityWindow(rt, op, args, count, 2);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 3);

    return makePromiseAsync<bool>(
      rt, op,
      [key = std::move(key), newAc, newWindow,
       prompt = std::move(prompt)]() mutable -> bool {
        // Slot bytes pass through verbatim — no parsing, no unwrap.
        // The bytes carry the same outer slot kind on both sides; we
        // pull it from metadata() for the new write.
        auto md = requireMetadata(key, "secure_kv_change_access_control");
        auto raw = SecureKVBackend::get(key, prompt);
        if (!raw.has_value()) {
          throw std::runtime_error(
            "secure_kv_change_access_control: key not found");
        }
        std::vector<uint8_t> stored = std::move(*raw);
        try {
          SecureKVBackend::set(
            key, stored.data(), stored.size(),
            newAc, newWindow, md.slotKind, prompt);
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

// --- bip32_export_seed ---------------------------------------------------

jsi::Value invoke_bip32_export_seed(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_bip32_export_seed";
    std::string key = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, key);
    std::string exportPp = parsePassphrase(rt, op, args, count, 1);
    if (exportPp.empty()) {
      throw jsi::JSError(
        rt, std::string(op) + ": exportPassphrase must be non-empty");
    }
    std::string storagePp = parsePassphrase(rt, op, args, count, 2);
    uint32_t exportIters =
      parsePassphraseIters(rt, op, args, count, 3, kKdfDefaultIters);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 4);

    return makePromiseAsync<std::vector<uint8_t>>(
      rt, op,
      [key = std::move(key), exportPp = std::move(exportPp),
       storagePp = std::move(storagePp), exportIters,
       prompt = std::move(prompt)]() -> std::vector<uint8_t> {
        auto raw = SecureKVBackend::get(key, prompt);
        if (!raw.has_value()) {
          throw std::runtime_error(
            "secure_kv_bip32_export_seed: key not found");
        }
        std::vector<uint8_t> inner =
          unwrapToInner(std::move(*raw), storagePp);
        // inner must be a SEED slot. Anything else is a misuse — exit
        // before we hand the bytes off to wrapPassphraseEnvelope.
        if (inner.empty() ||
            inner[0] != static_cast<uint8_t>(SlotKind::Bip32Seed)) {
          memzero(inner.data(), inner.size());
          throw std::runtime_error(
            "secure_kv_bip32_export_seed: slot is not a SEED");
        }
        std::vector<uint8_t> envelope;
        try {
          envelope = wrapPassphraseEnvelope(
            inner.data(), inner.size(), exportPp, exportIters);
        } catch (...) {
          memzero(inner.data(), inner.size());
          throw;
        }
        memzero(inner.data(), inner.size());
        return envelope;
      },
      [](jsi::Runtime& rt, std::vector<uint8_t>&& env) -> jsi::Value {
        return wrapDigest(rt, std::move(env));
      }
    );
  });
}

// --- bip32_import_seed ---------------------------------------------------

jsi::Value invoke_bip32_import_seed(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_bip32_import_seed";
    std::string key = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, key);
    auto envelope = requireArrayBufferAt(rt, op, "envelope", args, count, 1);
    std::string exportPp = parsePassphrase(rt, op, args, count, 2);
    if (exportPp.empty()) {
      throw jsi::JSError(
        rt, std::string(op) + ": exportPassphrase must be non-empty");
    }
    std::string acStr = requireStringAt(rt, op, "accessControl", args, count, 3);
    AccessControl ac = parseAccessControl(rt, op, acStr);
    uint32_t window = parseValidityWindow(rt, op, args, count, 4);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 5);
    std::string storagePp = parsePassphrase(rt, op, args, count, 8);
    uint32_t storageIters =
      parsePassphraseIters(rt, op, args, count, 9, kKdfDefaultIters);

    // Copy envelope bytes into a vector now (JS thread) so the worker
    // can use them after the ArrayBuffer goes out of scope.
    std::vector<uint8_t> envBytes(
      envelope.data(rt), envelope.data(rt) + envelope.size(rt));

    return makePromiseAsync<bool>(
      rt, op,
      [key = std::move(key), envBytes = std::move(envBytes),
       exportPp = std::move(exportPp),
       storagePp = std::move(storagePp), storageIters,
       ac, window,
       prompt = std::move(prompt)]() mutable -> bool {
        // Decrypt the envelope to recover the inner SEED slot.
        std::vector<uint8_t> inner;
        try {
          inner = unwrapPassphraseEnvelope(
            envBytes.data(), envBytes.size(), exportPp);
        } catch (...) {
          memzero(envBytes.data(), envBytes.size());
          throw;
        }
        memzero(envBytes.data(), envBytes.size());

        if (inner.empty() ||
            inner[0] != static_cast<uint8_t>(SlotKind::Bip32Seed)) {
          memzero(inner.data(), inner.size());
          throw std::runtime_error(
            "secure_kv_bip32_import_seed: envelope inner slot is not a SEED");
        }

        std::vector<uint8_t> stored;
        uint8_t slotKind;
        if (storagePp.empty()) {
          slotKind = static_cast<uint8_t>(SlotKind::Bip32Seed);
          stored = std::move(inner);
        } else {
          try {
            stored = wrapPassphraseEnvelope(
              inner.data(), inner.size(), storagePp, storageIters);
          } catch (...) {
            memzero(inner.data(), inner.size());
            throw;
          }
          memzero(inner.data(), inner.size());
          slotKind = static_cast<uint8_t>(SlotKind::PassphraseWrapped);
        }

        try {
          SecureKVBackend::set(
            key, stored.data(), stored.size(),
            ac, window, slotKind, prompt);
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

}  // namespace

void registerSecureKVBackupMethods(MethodMap& map) {
  // changePassphrase: key, oldPp, newPp, promptT, promptS, promptC, newIters
  map.push_back(
    {"secure_kv_change_passphrase", 7, invoke_change_passphrase});
  // changeAccessControl: key, accessControl, window, promptT, promptS, promptC
  map.push_back(
    {"secure_kv_change_access_control", 6, invoke_change_access_control});
  // bip32_export_seed: alias, exportPp, storagePp, exportIters,
  //                    promptT, promptS, promptC
  map.push_back(
    {"secure_kv_bip32_export_seed", 7, invoke_bip32_export_seed});
  // bip32_import_seed: newAlias, envelope, exportPp, accessControl, window,
  //                    promptT, promptS, promptC, storagePp, storageIters
  map.push_back(
    {"secure_kv_bip32_import_seed", 10, invoke_bip32_import_seed});
}

}  // namespace facebook::react::cryptolib

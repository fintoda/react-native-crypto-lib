// Native-only signing on top of SecureKV slots.
//
// Two slot families:
//   - SEED  (0x01): a 16..64-byte BIP-32 / SLIP-10 seed (the BIP-32 spec
//                   range; the typical bip39.toSeed output is 64 bytes).
//                   Sign-side methods derive a leaf key on the fly and
//                   never expose it.
//   - RAW   (0x02): a single 32-byte private scalar bound to a curve.
//                   No derivation; the curve was fixed at provisioning time.
//
// Every operation pulls the encrypted blob from the platform backend
// (Keychain / AndroidKeystore via cpp/SecureKVBackend.h), parses the
// slot, runs the crypto, and memzero's both the slot bytes and any
// derived material before returning. The private key never crosses the
// JSI boundary.
//
// All thunks dispatch the backend call (and the crypto that follows it)
// to a worker thread via makePromiseAsync — the platform layer can
// block on a biometric prompt for tens of seconds, and we don't want
// the JS thread frozen while that happens. The Phase 1 validation
// (charset, length, curve) still runs synchronously on the JS thread,
// wrapped by safeAsyncThunk so jsi::JSError throws surface as Promise
// rejections rather than synchronous JS-side throws.
//
// Path encoding follows cpp/Bip32.cpp: a packed ArrayBuffer of 4-byte
// big-endian uint32 indices (4 * N bytes for an N-step path). The TS
// wrapper layer converts the conventional "m/44'/0'/0'/0/0" string form
// into this packed buffer.

#include "Common.h"
#include "SchnorrInternal.h"
#include "SecureKVBackend.h"
#include "SecureKVCommon.h"
#include "SecureKVPassphrase.h"
#include "SecureKVSlot.h"

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include "bip32.h"
#include "curves.h"
#include "ecdsa.h"
#include "ed25519.h"
#include "memzero.h"
#include "nist256p1.h"
#include "secp256k1.h"
}

namespace facebook::react::cryptolib {
namespace {

uint8_t curveTagFromString(const std::string& s) {
  if (s == "secp256k1") return kCurveTagSecp256k1;
  if (s == "nist256p1") return kCurveTagNist256p1;
  if (s == "ed25519")   return kCurveTagEd25519;
  return 0xff;
}

const char* curveNameFromTag(uint8_t tag) {
  switch (tag) {
    case kCurveTagSecp256k1: return "secp256k1";
    case kCurveTagNist256p1: return "nist256p1";
    case kCurveTagEd25519:   return "ed25519";
    default: return nullptr;
  }
}

const ecdsa_curve* ecdsaCurveFromTag(uint8_t tag) {
  switch (tag) {
    case kCurveTagSecp256k1: return &secp256k1;
    case kCurveTagNist256p1: return &nist256p1;
    default: return nullptr;
  }
}

// --- Slot access -----------------------------------------------------------

// RAII for the raw slot bytes pulled from the backend. memzero on destruct.
struct ScrubbedSlot {
  std::vector<uint8_t> bytes;
  ~ScrubbedSlot() { if (!bytes.empty()) memzero(bytes.data(), bytes.size()); }
};

// Used inside bgWork (worker thread) — throws std::runtime_error rather
// than jsi::JSError because no jsi::Runtime is available here. The
// caught message is propagated back to JS by makePromiseAsync.
//
// Transparent passphrase unwrap: if the outer slot is PassphraseWrapped,
// `passphrase` is required and the returned ScrubbedSlot.bytes hold the
// inner slot (post-decrypt). Callers that don't care about wrapping
// just see the inner slot kind.
ScrubbedSlot loadSlotOrThrow(
  const std::string& alias,
  const BiometricPromptCopy& prompt = {},
  const std::string& passphrase = ""
) {
  auto raw = SecureKVBackend::get(alias, prompt);
  if (!raw.has_value()) {
    throw std::runtime_error("key not found");
  }
  ScrubbedSlot blob{std::move(*raw)};
  // Peek at the outer slot tag without parsing into payload — we just
  // need the kind to decide whether to unwrap.
  if (!blob.bytes.empty() &&
      blob.bytes[0] == static_cast<uint8_t>(SlotKind::PassphraseWrapped)) {
    if (passphrase.empty()) {
      throw std::runtime_error("passphrase: required");
    }
    auto inner = unwrapPassphraseEnvelope(
      blob.bytes.data(), blob.bytes.size(), passphrase);
    // Move inner over outer; ScrubbedSlot dtor will zero the inner bytes.
    blob.bytes = std::move(inner);
  }
  return blob;
}

void parseSlotOrThrow(const ScrubbedSlot& blob, SlotView& out) {
  if (!parseSlot(blob.bytes.data(), blob.bytes.size(), out)) {
    throw std::runtime_error("slot is empty or malformed");
  }
}

void requireSlotKind(const SlotView& slot, SlotKind expected) {
  if (slot.kind != expected) {
    throw std::runtime_error(
      std::string("slot is ") + slotKindName(slot.kind) +
        ", expected " + slotKindName(expected));
  }
}

void requirePayloadLen(const SlotView& slot, size_t expected) {
  if (slot.payloadLen != expected) {
    throw std::runtime_error(
      "slot payload corrupt (expected " + std::to_string(expected) +
        " bytes, got " + std::to_string(slot.payloadLen) + ")");
  }
}

void requireSeedPayloadLen(const SlotView& slot) {
  if (slot.payloadLen < kMinSeedPayloadLen ||
      slot.payloadLen > kMaxSeedPayloadLen) {
    throw std::runtime_error(
      "seed slot has out-of-range length " + std::to_string(slot.payloadLen));
  }
}

// --- Path parsing ----------------------------------------------------------

// Validates the path ArrayBuffer (multiple of 4 bytes, ≤ ~32 levels) and
// copies it into a vector so the bytes survive past the JS-thread thunk
// frame (we hand them to a worker thread).
struct PathArg {
  std::vector<uint8_t> data;
  size_t steps;
};

PathArg readPath(
  jsi::Runtime& rt,
  const char* op,
  const jsi::ArrayBuffer& path
) {
  size_t len = path.size(rt);
  if (len % 4 != 0) {
    throw jsi::JSError(
      rt, std::string(op) + ": path must be a multiple of 4 bytes");
  }
  if (len > 4 * 32) {
    throw jsi::JSError(
      rt, std::string(op) + ": path too deep (max 32 levels)");
  }
  PathArg out;
  out.steps = len / 4;
  out.data.assign(path.data(rt), path.data(rt) + len);
  return out;
}

uint32_t readBeU32(const uint8_t* src) {
  return (static_cast<uint32_t>(src[0]) << 24) |
         (static_cast<uint32_t>(src[1]) << 16) |
         (static_cast<uint32_t>(src[2]) << 8) |
         static_cast<uint32_t>(src[3]);
}

// --- Derivation ------------------------------------------------------------

struct DerivedKey {
  uint8_t priv[32];
  uint8_t pub[33];   // compressed (or 0x00||ed25519-pub for SLIP-10 ed25519)
  uint32_t fingerprint;
};

// Throws std::runtime_error on failure (worker-thread-safe — no jsi).
// memzero's all internal HDNode state before returning.
void deriveFromSeed(
  const uint8_t* seed,
  size_t seedLen,
  uint8_t curveTag,
  const uint8_t* pathBytes,
  size_t pathSteps,
  DerivedKey& out
) {
  const char* curveName = curveNameFromTag(curveTag);
  if (!curveName) {
    throw std::runtime_error("unknown curve");
  }
  HDNode node;
  std::memset(&node, 0, sizeof(node));
  if (hdnode_from_seed(seed, static_cast<int>(seedLen), curveName, &node) != 1) {
    memzero(&node, sizeof(node));
    throw std::runtime_error("seed rejected");
  }
  for (size_t i = 0; i < pathSteps; ++i) {
    uint32_t index = readBeU32(pathBytes + i * 4);
    if (hdnode_private_ckd(&node, index) != 1) {
      memzero(&node, sizeof(node));
      throw std::runtime_error("derivation failed");
    }
  }
  hdnode_fill_public_key(&node);
  out.fingerprint = hdnode_fingerprint(&node);
  std::memcpy(out.priv, node.private_key, 32);
  std::memcpy(out.pub, node.public_key, 33);
  memzero(&node, sizeof(node));
}

// Vector return alias used across most thunks.
using ByteVec = std::vector<uint8_t>;

// Helper: parse RAW slot, copy into RawKey, optionally enforce a curve.
struct RawKey {
  uint8_t curveTag;
  uint8_t priv[32];
};

void loadRawKey(
  const std::string& alias,
  RawKey& out,
  int requiredCurveTag, /* -1 = any */
  const BiometricPromptCopy& prompt = {},
  const std::string& passphrase = ""
) {
  ScrubbedSlot blob = loadSlotOrThrow(alias, prompt, passphrase);
  SlotView slot;
  parseSlotOrThrow(blob, slot);
  requireSlotKind(slot, SlotKind::RawPrivate);
  requirePayloadLen(slot, kRawPayloadLen);

  out.curveTag = slot.payload[0];
  std::memcpy(out.priv, slot.payload + 1, 32);

  if (requiredCurveTag >= 0 &&
      out.curveTag != static_cast<uint8_t>(requiredCurveTag)) {
    auto have = curveNameFromTag(out.curveTag);
    auto want = curveNameFromTag(static_cast<uint8_t>(requiredCurveTag));
    memzero(&out, sizeof(out));
    throw std::runtime_error(
      std::string("slot curve is ") +
        (have ? have : "unknown") +
        ", expected " +
        (want ? want : "unknown"));
  }
}

// --- BIP-32 / SEED slot thunks ---------------------------------------------

jsi::Value invoke_bip32_set_seed(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_bip32_set_seed";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto seed = requireArrayBufferAt(rt, op, "seed", args, count, 1);
    size_t len = seed.size(rt);
    if (len < kMinSeedPayloadLen || len > kMaxSeedPayloadLen) {
      throw jsi::JSError(
        rt, std::string(op) + ": seed must be 16..64 bytes (BIP-32 spec)");
    }
    std::string acStr = requireStringAt(rt, op, "accessControl", args, count, 2);
    AccessControl ac = parseAccessControl(rt, op, acStr);
    uint32_t window = parseValidityWindow(rt, op, args, count, 3);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 4);
    std::string passphrase = parsePassphrase(rt, op, args, count, 7);
    uint32_t iters = parsePassphraseIters(rt, op, args, count, 8, kKdfDefaultIters);

    std::vector<uint8_t> innerSlot = wrapSeedSlot(seed.data(rt), len);
    std::vector<uint8_t> stored;
    uint8_t slotKind;
    if (passphrase.empty()) {
      stored = std::move(innerSlot);
      slotKind = static_cast<uint8_t>(SlotKind::Bip32Seed);
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
      rt, op,
      [alias = std::move(alias), stored = std::move(stored), ac, window, slotKind,
       prompt = std::move(prompt)]() mutable -> bool {
        try {
          SecureKVBackend::set(
            alias, stored.data(), stored.size(), ac, window, slotKind, prompt);
        } catch (...) {
          memzero(stored.data(), stored.size());
          throw;
        }
        memzero(stored.data(), stored.size());
        return true;
      },
      [](jsi::Runtime&, bool&&) -> jsi::Value { return jsi::Value::undefined(); }
    );
  });
}

jsi::Value invoke_bip32_fingerprint(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_bip32_fingerprint";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
    std::string curveStr = requireStringAt(rt, op, "curve", args, count, 2);
    uint8_t curveTag = curveTagFromString(curveStr);
    if (curveTag == 0xff) {
      throw jsi::JSError(rt, std::string(op) + ": unknown curve");
    }
    PathArg p = readPath(rt, op, path);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 3);
    std::string passphrase = parsePassphrase(rt, op, args, count, 6);

    return makePromiseAsync<uint32_t>(
      rt, op,
      [alias = std::move(alias), p = std::move(p), curveTag,
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> uint32_t {
        ScrubbedSlot blob = loadSlotOrThrow(alias, prompt, passphrase);
        SlotView slot;
        parseSlotOrThrow(blob, slot);
        requireSlotKind(slot, SlotKind::Bip32Seed);
        requireSeedPayloadLen(slot);

        DerivedKey k;
        std::memset(&k, 0, sizeof(k));
        deriveFromSeed(
          slot.payload, slot.payloadLen, curveTag,
          p.data.data(), p.steps, k);
        uint32_t fp = k.fingerprint;
        memzero(&k, sizeof(k));
        return fp;
      },
      [](jsi::Runtime&, uint32_t&& fp) -> jsi::Value {
        return jsi::Value(static_cast<double>(fp));
      }
    );
  });
}

jsi::Value invoke_bip32_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_bip32_get_public";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
    std::string curveStr = requireStringAt(rt, op, "curve", args, count, 2);
    bool compact = requireBoolAt(rt, op, "compact", args, count, 3);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 4);
    uint8_t curveTag = curveTagFromString(curveStr);
    if (curveTag == 0xff) {
      throw jsi::JSError(rt, std::string(op) + ": unknown curve");
    }
    PathArg p = readPath(rt, op, path);
    std::string passphrase = parsePassphrase(rt, op, args, count, 7);

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), p = std::move(p), curveTag, compact,
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        ScrubbedSlot blob = loadSlotOrThrow(alias, prompt, passphrase);
        SlotView slot;
        parseSlotOrThrow(blob, slot);
        requireSlotKind(slot, SlotKind::Bip32Seed);
        requireSeedPayloadLen(slot);

        DerivedKey k;
        std::memset(&k, 0, sizeof(k));
        deriveFromSeed(
          slot.payload, slot.payloadLen, curveTag,
          p.data.data(), p.steps, k);

        ByteVec out;
        if (curveTag == kCurveTagEd25519) {
          out.assign(k.pub + 1, k.pub + 33);
        } else if (compact) {
          out.assign(k.pub, k.pub + 33);
        } else {
          const ecdsa_curve* curve = ecdsaCurveFromTag(curveTag);
          curve_point point = {};
          if (ecdsa_read_pubkey(curve, k.pub, &point) == 0) {
            memzero(&point, sizeof(point));
            memzero(&k, sizeof(k));
            throw std::runtime_error("derived pubkey invalid");
          }
          out.resize(65);
          out[0] = 0x04;
          bn_write_be(&point.x, out.data() + 1);
          bn_write_be(&point.y, out.data() + 33);
          memzero(&point, sizeof(point));
        }
        memzero(&k, sizeof(k));
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

jsi::Value invoke_bip32_sign_ecdsa(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_bip32_sign_ecdsa";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
    auto digest = requireArrayBufferAt(rt, op, "digest", args, count, 2);
    std::string curveStr = requireStringAt(rt, op, "curve", args, count, 3);
    if (digest.size(rt) != 32) {
      throw jsi::JSError(rt, std::string(op) + ": digest must be 32 bytes");
    }
    uint8_t curveTag = curveTagFromString(curveStr);
    const ecdsa_curve* curve = ecdsaCurveFromTag(curveTag);
    if (!curve) {
      throw jsi::JSError(
        rt, std::string(op) + ": curve must be secp256k1 or nist256p1");
    }
    PathArg p = readPath(rt, op, path);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 4);
    std::string passphrase = parsePassphrase(rt, op, args, count, 7);
    ByteVec digestBytes(digest.data(rt), digest.data(rt) + 32);

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), p = std::move(p),
       digestBytes = std::move(digestBytes),
       curveTag, curve, prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        ScrubbedSlot blob = loadSlotOrThrow(alias, prompt, passphrase);
        SlotView slot;
        parseSlotOrThrow(blob, slot);
        requireSlotKind(slot, SlotKind::Bip32Seed);
        requireSeedPayloadLen(slot);

        DerivedKey k;
        std::memset(&k, 0, sizeof(k));
        deriveFromSeed(
          slot.payload, slot.payloadLen, curveTag,
          p.data.data(), p.steps, k);

        ByteVec out(65);
        uint8_t pby = 0;
        int err = ecdsa_sign_digest(
          curve, k.priv, digestBytes.data(), out.data() + 1, &pby, nullptr);
        memzero(&k, sizeof(k));
        if (err != 0) {
          memzero(out.data(), out.size());
          throw std::runtime_error("signing failed");
        }
        out[0] = pby;
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

// Body shared by plain Schnorr and Schnorr-Taproot for SEED slots.
jsi::Value invoke_bip32_sign_schnorr_impl(
  jsi::Runtime& rt,
  const jsi::Value* args,
  size_t count,
  const char* op,
  bool taproot
) {
  return safeAsyncThunk(rt, [&] {
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
    auto digest = requireArrayBufferAt(rt, op, "digest", args, count, 2);
    if (digest.size(rt) != 32) {
      throw jsi::JSError(rt, std::string(op) + ": digest must be 32 bytes");
    }
    // Optional aux/merkleRoot at index 3.
    ByteVec extraBytes;
    bool hasExtra = false;
    if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
      auto extra = requireArrayBufferAt(
        rt, op, taproot ? "merkleRoot" : "aux", args, count, 3);
      size_t elen = extra.size(rt);
      if (!taproot && elen != 32) {
        throw jsi::JSError(rt, std::string(op) + ": aux must be 32 bytes");
      }
      extraBytes.assign(extra.data(rt), extra.data(rt) + elen);
      hasExtra = true;
    }
    PathArg p = readPath(rt, op, path);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 4);
    std::string passphrase = parsePassphrase(rt, op, args, count, 7);
    ByteVec digestBytes(digest.data(rt), digest.data(rt) + 32);

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), p = std::move(p),
       digestBytes = std::move(digestBytes),
       extraBytes = std::move(extraBytes), hasExtra, taproot,
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        ScrubbedSlot blob = loadSlotOrThrow(alias, prompt, passphrase);
        SlotView slot;
        parseSlotOrThrow(blob, slot);
        requireSlotKind(slot, SlotKind::Bip32Seed);
        requireSeedPayloadLen(slot);

        DerivedKey k;
        std::memset(&k, 0, sizeof(k));
        deriveFromSeed(
          slot.payload, slot.payloadLen, kCurveTagSecp256k1,
          p.data.data(), p.steps, k);

        uint8_t signingPriv[32];
        const uint8_t* extraPtr = hasExtra ? extraBytes.data() : nullptr;
        size_t extraLen = hasExtra ? extraBytes.size() : 0;
        if (taproot) {
          if (!schnorr_internal::tweakPrivate(
                k.priv, extraPtr, extraLen, signingPriv)) {
            memzero(&k, sizeof(k));
            memzero(signingPriv, sizeof(signingPriv));
            throw std::runtime_error("tap-tweak failed");
          }
        } else {
          std::memcpy(signingPriv, k.priv, 32);
        }
        memzero(&k, sizeof(k));

        ByteVec out(64);
        bool ok = schnorr_internal::sign(
          signingPriv, digestBytes.data(),
          taproot ? nullptr : extraPtr,
          out.data());
        memzero(signingPriv, sizeof(signingPriv));
        if (!ok) {
          memzero(out.data(), out.size());
          throw std::runtime_error("signing failed");
        }
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

jsi::Value invoke_bip32_sign_schnorr(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return invoke_bip32_sign_schnorr_impl(
    rt, args, count, "secure_kv_bip32_sign_schnorr", /*taproot*/ false);
}

jsi::Value invoke_bip32_sign_schnorr_taproot(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return invoke_bip32_sign_schnorr_impl(
    rt, args, count, "secure_kv_bip32_sign_schnorr_taproot", /*taproot*/ true);
}

jsi::Value invoke_bip32_sign_ed25519(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_bip32_sign_ed25519";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
    auto msg = requireArrayBufferAt(rt, op, "msg", args, count, 2);
    PathArg p = readPath(rt, op, path);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 3);
    std::string passphrase = parsePassphrase(rt, op, args, count, 6);
    ByteVec msgBytes;
    msgBytes.assign(safeData(rt, msg), safeData(rt, msg) + msg.size(rt));

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), p = std::move(p),
       msgBytes = std::move(msgBytes),
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        ScrubbedSlot blob = loadSlotOrThrow(alias, prompt, passphrase);
        SlotView slot;
        parseSlotOrThrow(blob, slot);
        requireSlotKind(slot, SlotKind::Bip32Seed);
        requireSeedPayloadLen(slot);

        DerivedKey k;
        std::memset(&k, 0, sizeof(k));
        deriveFromSeed(
          slot.payload, slot.payloadLen, kCurveTagEd25519,
          p.data.data(), p.steps, k);

        ByteVec out(64);
        // ed25519_sign requires non-NULL msg pointer even at len=0.
        const uint8_t kEmpty = 0;
        const uint8_t* mp = msgBytes.empty() ? &kEmpty : msgBytes.data();
        ed25519_sign(mp, msgBytes.size(), k.priv, out.data());
        memzero(&k, sizeof(k));
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

jsi::Value invoke_bip32_ecdh(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_bip32_ecdh";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
    auto pub = requireArrayBufferAt(rt, op, "peerPub", args, count, 2);
    std::string curveStr = requireStringAt(rt, op, "curve", args, count, 3);
    size_t publen = pub.size(rt);
    if (publen != 33 && publen != 65) {
      throw jsi::JSError(rt, std::string(op) + ": peerPub must be 33 or 65 bytes");
    }
    uint8_t curveTag = curveTagFromString(curveStr);
    const ecdsa_curve* curve = ecdsaCurveFromTag(curveTag);
    if (!curve) {
      throw jsi::JSError(
        rt, std::string(op) + ": curve must be secp256k1 or nist256p1");
    }
    PathArg p = readPath(rt, op, path);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 4);
    std::string passphrase = parsePassphrase(rt, op, args, count, 7);
    ByteVec pubBytes(pub.data(rt), pub.data(rt) + publen);

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), p = std::move(p), pubBytes = std::move(pubBytes),
       curveTag, curve, prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        (void)curveTag;
        ScrubbedSlot blob = loadSlotOrThrow(alias, prompt, passphrase);
        SlotView slot;
        parseSlotOrThrow(blob, slot);
        requireSlotKind(slot, SlotKind::Bip32Seed);
        requireSeedPayloadLen(slot);

        DerivedKey k;
        std::memset(&k, 0, sizeof(k));
        deriveFromSeed(
          slot.payload, slot.payloadLen, curveTag,
          p.data.data(), p.steps, k);

        uint8_t full[65];
        int err = ecdh_multiply(curve, k.priv, pubBytes.data(), full);
        memzero(&k, sizeof(k));
        if (err != 0) {
          memzero(full, sizeof(full));
          throw std::runtime_error("shared secret computation failed");
        }
        ByteVec out(33);
        out[0] = 0x02 | (full[64] & 0x01);
        std::memcpy(out.data() + 1, full + 1, 32);
        memzero(full, sizeof(full));
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

// --- RAW slot thunks --------------------------------------------------------

jsi::Value invoke_raw_set_private(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_raw_set_private";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto priv = requireArrayBufferAt(rt, op, "priv", args, count, 1);
    std::string curveStr = requireStringAt(rt, op, "curve", args, count, 2);
    if (priv.size(rt) != 32) {
      throw jsi::JSError(rt, std::string(op) + ": priv must be 32 bytes");
    }
    uint8_t curveTag = curveTagFromString(curveStr);
    if (curveTag == 0xff) {
      throw jsi::JSError(rt, std::string(op) + ": unknown curve");
    }
    // For ECDSA curves, validate the scalar lies in [1, n-1] before storing
    // — otherwise sign-time would surface a confusing "invalid private key".
    // Ed25519 accepts any 32-byte seed (clamped internally), so skip there.
    if (curveTag == kCurveTagSecp256k1 || curveTag == kCurveTagNist256p1) {
      const ecdsa_curve* curve = ecdsaCurveFromTag(curveTag);
      uint8_t probe[33];
      if (ecdsa_get_public_key33(curve, priv.data(rt), probe) != 0) {
        memzero(probe, sizeof(probe));
        throw jsi::JSError(
          rt, std::string(op) + ": private key out of range for curve");
      }
      memzero(probe, sizeof(probe));
    }
    std::string acStr = requireStringAt(rt, op, "accessControl", args, count, 3);
    AccessControl ac = parseAccessControl(rt, op, acStr);
    uint32_t window = parseValidityWindow(rt, op, args, count, 4);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 5);
    std::string passphrase = parsePassphrase(rt, op, args, count, 8);
    uint32_t iters = parsePassphraseIters(rt, op, args, count, 9, kKdfDefaultIters);

    std::vector<uint8_t> innerSlot = wrapRawSlot(curveTag, priv.data(rt));
    std::vector<uint8_t> stored;
    uint8_t slotKind;
    if (passphrase.empty()) {
      stored = std::move(innerSlot);
      slotKind = static_cast<uint8_t>(SlotKind::RawPrivate);
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
      rt, op,
      [alias = std::move(alias), stored = std::move(stored), ac, window, slotKind,
       prompt = std::move(prompt)]() mutable -> bool {
        try {
          SecureKVBackend::set(
            alias, stored.data(), stored.size(), ac, window, slotKind, prompt);
        } catch (...) {
          memzero(stored.data(), stored.size());
          throw;
        }
        memzero(stored.data(), stored.size());
        return true;
      },
      [](jsi::Runtime&, bool&&) -> jsi::Value { return jsi::Value::undefined(); }
    );
  });
}

jsi::Value invoke_raw_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_raw_get_public";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    bool compact = requireBoolAt(rt, op, "compact", args, count, 1);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 2);
    std::string passphrase = parsePassphrase(rt, op, args, count, 5);

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), compact,
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        RawKey k;
        loadRawKey(alias, k, -1, prompt, passphrase);

        ByteVec out;
        if (k.curveTag == kCurveTagEd25519) {
          out.resize(32);
          ed25519_publickey(k.priv, out.data());
        } else {
          const ecdsa_curve* curve = ecdsaCurveFromTag(k.curveTag);
          out.resize(compact ? 33 : 65);
          int err = compact
            ? ecdsa_get_public_key33(curve, k.priv, out.data())
            : ecdsa_get_public_key65(curve, k.priv, out.data());
          if (err != 0) {
            memzero(&k, sizeof(k));
            throw std::runtime_error("invalid private key");
          }
        }
        memzero(&k, sizeof(k));
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

jsi::Value invoke_raw_sign_ecdsa(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_raw_sign_ecdsa";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto digest = requireArrayBufferAt(rt, op, "digest", args, count, 1);
    if (digest.size(rt) != 32) {
      throw jsi::JSError(rt, std::string(op) + ": digest must be 32 bytes");
    }
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 2);
    std::string passphrase = parsePassphrase(rt, op, args, count, 5);
    ByteVec digestBytes(digest.data(rt), digest.data(rt) + 32);

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), digestBytes = std::move(digestBytes),
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        RawKey k;
        loadRawKey(alias, k, -1, prompt, passphrase);
        if (k.curveTag != kCurveTagSecp256k1 &&
            k.curveTag != kCurveTagNist256p1) {
          memzero(&k, sizeof(k));
          throw std::runtime_error(
            "ECDSA requires secp256k1 or nist256p1 slot");
        }
        const ecdsa_curve* curve = ecdsaCurveFromTag(k.curveTag);
        ByteVec out(65);
        uint8_t pby = 0;
        int err = ecdsa_sign_digest(
          curve, k.priv, digestBytes.data(), out.data() + 1, &pby, nullptr);
        memzero(&k, sizeof(k));
        if (err != 0) {
          memzero(out.data(), out.size());
          throw std::runtime_error("signing failed");
        }
        out[0] = pby;
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

jsi::Value invoke_raw_sign_schnorr_impl(
  jsi::Runtime& rt,
  const jsi::Value* args,
  size_t count,
  const char* op,
  bool taproot
) {
  return safeAsyncThunk(rt, [&] {
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto digest = requireArrayBufferAt(rt, op, "digest", args, count, 1);
    if (digest.size(rt) != 32) {
      throw jsi::JSError(rt, std::string(op) + ": digest must be 32 bytes");
    }
    ByteVec extraBytes;
    bool hasExtra = false;
    if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
      auto extra = requireArrayBufferAt(
        rt, op, taproot ? "merkleRoot" : "aux", args, count, 2);
      size_t elen = extra.size(rt);
      if (!taproot && elen != 32) {
        throw jsi::JSError(rt, std::string(op) + ": aux must be 32 bytes");
      }
      extraBytes.assign(extra.data(rt), extra.data(rt) + elen);
      hasExtra = true;
    }
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 3);
    std::string passphrase = parsePassphrase(rt, op, args, count, 6);
    ByteVec digestBytes(digest.data(rt), digest.data(rt) + 32);

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias),
       digestBytes = std::move(digestBytes),
       extraBytes = std::move(extraBytes), hasExtra, taproot,
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        RawKey k;
        loadRawKey(alias, k, kCurveTagSecp256k1, prompt, passphrase);

        uint8_t signingPriv[32];
        const uint8_t* extraPtr = hasExtra ? extraBytes.data() : nullptr;
        size_t extraLen = hasExtra ? extraBytes.size() : 0;
        if (taproot) {
          if (!schnorr_internal::tweakPrivate(
                k.priv, extraPtr, extraLen, signingPriv)) {
            memzero(&k, sizeof(k));
            memzero(signingPriv, sizeof(signingPriv));
            throw std::runtime_error("tap-tweak failed");
          }
        } else {
          std::memcpy(signingPriv, k.priv, 32);
        }
        memzero(&k, sizeof(k));

        ByteVec out(64);
        bool ok = schnorr_internal::sign(
          signingPriv, digestBytes.data(),
          taproot ? nullptr : extraPtr,
          out.data());
        memzero(signingPriv, sizeof(signingPriv));
        if (!ok) {
          memzero(out.data(), out.size());
          throw std::runtime_error("signing failed");
        }
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

jsi::Value invoke_raw_sign_schnorr(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return invoke_raw_sign_schnorr_impl(
    rt, args, count, "secure_kv_raw_sign_schnorr", /*taproot*/ false);
}

jsi::Value invoke_raw_sign_schnorr_taproot(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return invoke_raw_sign_schnorr_impl(
    rt, args, count, "secure_kv_raw_sign_schnorr_taproot", /*taproot*/ true);
}

jsi::Value invoke_raw_sign_ed25519(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_raw_sign_ed25519";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto msg = requireArrayBufferAt(rt, op, "msg", args, count, 1);
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 2);
    std::string passphrase = parsePassphrase(rt, op, args, count, 5);
    ByteVec msgBytes;
    msgBytes.assign(safeData(rt, msg), safeData(rt, msg) + msg.size(rt));

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), msgBytes = std::move(msgBytes),
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        RawKey k;
        loadRawKey(alias, k, kCurveTagEd25519, prompt, passphrase);

        ByteVec out(64);
        const uint8_t kEmpty = 0;
        const uint8_t* mp = msgBytes.empty() ? &kEmpty : msgBytes.data();
        ed25519_sign(mp, msgBytes.size(), k.priv, out.data());
        memzero(&k, sizeof(k));
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

jsi::Value invoke_raw_ecdh(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    const char* op = "secure_kv_raw_ecdh";
    std::string alias = requireStringAt(rt, op, "key", args, count, 0);
    requireValidKey(rt, op, alias);
    auto pub = requireArrayBufferAt(rt, op, "peerPub", args, count, 1);
    size_t publen = pub.size(rt);
    if (publen != 33 && publen != 65) {
      throw jsi::JSError(rt, std::string(op) + ": peerPub must be 33 or 65 bytes");
    }
    BiometricPromptCopy prompt = parsePromptCopy(rt, op, args, count, 2);
    std::string passphrase = parsePassphrase(rt, op, args, count, 5);
    ByteVec pubBytes(pub.data(rt), pub.data(rt) + publen);

    return makePromiseAsync<ByteVec>(
      rt, op,
      [alias = std::move(alias), pubBytes = std::move(pubBytes),
       prompt = std::move(prompt),
       passphrase = std::move(passphrase)]() -> ByteVec {
        RawKey k;
        loadRawKey(alias, k, -1, prompt, passphrase);
        if (k.curveTag != kCurveTagSecp256k1 &&
            k.curveTag != kCurveTagNist256p1) {
          memzero(&k, sizeof(k));
          throw std::runtime_error(
            "ECDH requires secp256k1 or nist256p1 slot");
        }
        const ecdsa_curve* curve = ecdsaCurveFromTag(k.curveTag);
        uint8_t full[65];
        int err = ecdh_multiply(curve, k.priv, pubBytes.data(), full);
        memzero(&k, sizeof(k));
        if (err != 0) {
          memzero(full, sizeof(full));
          throw std::runtime_error("shared secret computation failed");
        }
        ByteVec out(33);
        out[0] = 0x02 | (full[64] & 0x01);
        std::memcpy(out.data() + 1, full + 1, 32);
        memzero(full, sizeof(full));
        return out;
      },
      [](jsi::Runtime& rt, ByteVec&& bg) -> jsi::Value {
        return wrapDigest(rt, std::move(bg));
      }
    );
  });
}

}  // namespace

void registerSecureKVSignMethods(MethodMap& map) {
  // BIP-32 / SLIP-10 derivation on a stored seed.
  // ArgCount = base + 3 prompt strings (title, subtitle, cancelLabel).
  map.push_back({"secure_kv_bip32_set_seed",            9, invoke_bip32_set_seed});
  map.push_back({"secure_kv_bip32_fingerprint",         7, invoke_bip32_fingerprint});
  map.push_back({"secure_kv_bip32_get_public",          8, invoke_bip32_get_public});
  map.push_back({"secure_kv_bip32_sign_ecdsa",          8, invoke_bip32_sign_ecdsa});
  map.push_back({"secure_kv_bip32_sign_schnorr",        8, invoke_bip32_sign_schnorr});
  map.push_back({"secure_kv_bip32_sign_schnorr_taproot",8, invoke_bip32_sign_schnorr_taproot});
  map.push_back({"secure_kv_bip32_sign_ed25519",        7, invoke_bip32_sign_ed25519});
  map.push_back({"secure_kv_bip32_ecdh",                8, invoke_bip32_ecdh});

  // Raw 32-byte private key without derivation.
  map.push_back({"secure_kv_raw_set_private",          10, invoke_raw_set_private});
  map.push_back({"secure_kv_raw_get_public",            6, invoke_raw_get_public});
  map.push_back({"secure_kv_raw_sign_ecdsa",            6, invoke_raw_sign_ecdsa});
  map.push_back({"secure_kv_raw_sign_schnorr",          7, invoke_raw_sign_schnorr});
  map.push_back({"secure_kv_raw_sign_schnorr_taproot",  7, invoke_raw_sign_schnorr_taproot});
  map.push_back({"secure_kv_raw_sign_ed25519",          6, invoke_raw_sign_ed25519});
  map.push_back({"secure_kv_raw_ecdh",                  6, invoke_raw_ecdh});
}

}  // namespace facebook::react::cryptolib

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
// slot, runs the crypto in-place on the C++ stack, and memzero's both
// the slot bytes and any derived material before returning. The private
// key never crosses the JSI boundary.
//
// Path encoding follows cpp/Bip32.cpp: a packed ArrayBuffer of 4-byte
// big-endian uint32 indices (4 * N bytes for an N-step path). The TS
// wrapper layer converts the conventional "m/44'/0'/0'/0/0" string form
// into this packed buffer.

#include "Common.h"
#include "SchnorrInternal.h"
#include "SecureKVBackend.h"
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

constexpr size_t kMaxKeyLen = 128;

bool isValidKeyChar(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

void requireValidAlias(
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

[[noreturn]] void rethrowAsJsi(
  jsi::Runtime& rt, const char* op, const std::exception& e
) {
  throw jsi::JSError(rt, std::string(op) + ": " + e.what());
}

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

ScrubbedSlot loadSlotOrThrow(
  jsi::Runtime& rt, const char* op, const std::string& alias
) {
  std::optional<std::vector<uint8_t>> result;
  try {
    result = SecureKVBackend::get(alias);
  } catch (const std::exception& e) {
    rethrowAsJsi(rt, op, e);
  }
  if (!result.has_value()) {
    throw jsi::JSError(rt, std::string(op) + ": key not found");
  }
  return ScrubbedSlot{std::move(*result)};
}

void requireSlotKind(
  jsi::Runtime& rt,
  const char* op,
  const SlotView& slot,
  SlotKind expected
) {
  if (slot.kind != expected) {
    throw jsi::JSError(
      rt,
      std::string(op) + ": slot is " + slotKindName(slot.kind) +
        ", expected " + slotKindName(expected));
  }
}

void requirePayloadLen(
  jsi::Runtime& rt,
  const char* op,
  const SlotView& slot,
  size_t expected
) {
  if (slot.payloadLen != expected) {
    throw jsi::JSError(
      rt,
      std::string(op) + ": slot payload corrupt (expected " +
        std::to_string(expected) + " bytes, got " +
        std::to_string(slot.payloadLen) + ")");
  }
}

void requireSeedPayloadLen(
  jsi::Runtime& rt, const char* op, const SlotView& slot
) {
  if (slot.payloadLen < kMinSeedPayloadLen ||
      slot.payloadLen > kMaxSeedPayloadLen) {
    throw jsi::JSError(
      rt,
      std::string(op) + ": seed slot has out-of-range length " +
        std::to_string(slot.payloadLen));
  }
}

// --- Path parsing ----------------------------------------------------------

// Validates the path ArrayBuffer (multiple of 4 bytes, ≤ ~32 levels) and
// returns step count + raw pointer to the BE-encoded indices.
struct PathArg {
  const uint8_t* data;
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
  return {len == 0 ? nullptr : path.data(rt), len / 4};
}

uint32_t readBeU32(const uint8_t* src) {
  return (static_cast<uint32_t>(src[0]) << 24) |
         (static_cast<uint32_t>(src[1]) << 16) |
         (static_cast<uint32_t>(src[2]) << 8) |
         static_cast<uint32_t>(src[3]);
}

// --- Derivation ------------------------------------------------------------

// Holds a derived child's material. Caller must memzero on use.
struct DerivedKey {
  uint8_t priv[32];
  uint8_t pub[33];   // compressed (or 0x00||ed25519-pub for SLIP-10 ed25519)
  uint32_t fingerprint;
};

// Derives a child key from the seed at the given path on the named curve.
// Throws jsi::JSError on failure. memzero's all internal HDNode state
// before returning.
void deriveFromSeed(
  jsi::Runtime& rt,
  const char* op,
  const uint8_t* seed,
  size_t seedLen,
  uint8_t curveTag,
  const uint8_t* pathBytes,
  size_t pathSteps,
  DerivedKey& out
) {
  const char* curveName = curveNameFromTag(curveTag);
  if (!curveName) {
    throw jsi::JSError(rt, std::string(op) + ": unknown curve");
  }
  HDNode node;
  std::memset(&node, 0, sizeof(node));
  if (hdnode_from_seed(seed, static_cast<int>(seedLen), curveName, &node) != 1) {
    memzero(&node, sizeof(node));
    throw jsi::JSError(rt, std::string(op) + ": seed rejected");
  }
  for (size_t i = 0; i < pathSteps; ++i) {
    uint32_t index = readBeU32(pathBytes + i * 4);
    if (hdnode_private_ckd(&node, index) != 1) {
      memzero(&node, sizeof(node));
      throw jsi::JSError(rt, std::string(op) + ": derivation failed");
    }
  }
  hdnode_fill_public_key(&node);
  out.fingerprint = hdnode_fingerprint(&node);
  std::memcpy(out.priv, node.private_key, 32);
  std::memcpy(out.pub, node.public_key, 33);
  memzero(&node, sizeof(node));
}

// --- BIP-32: setSeed -------------------------------------------------------

jsi::Value invoke_bip32_set_seed(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  std::string alias = requireStringAt(
    rt, "secure_kv_bip32_set_seed", "key", args, count, 0);
  requireValidAlias(rt, "secure_kv_bip32_set_seed", alias);
  auto seed = requireArrayBufferAt(
    rt, "secure_kv_bip32_set_seed", "seed", args, count, 1);
  size_t len = seed.size(rt);
  if (len < kMinSeedPayloadLen || len > kMaxSeedPayloadLen) {
    throw jsi::JSError(
      rt,
      "secure_kv_bip32_set_seed: seed must be 16..64 bytes (BIP-32 spec)");
  }
  auto wrapped = wrapSeedSlot(seed.data(rt), len);
  try {
    SecureKVBackend::set(alias, wrapped.data(), wrapped.size());
  } catch (const std::exception& e) {
    memzero(wrapped.data(), wrapped.size());
    rethrowAsJsi(rt, "secure_kv_bip32_set_seed", e);
  }
  memzero(wrapped.data(), wrapped.size());
  return jsi::Value::undefined();
}

// --- BIP-32: fingerprint ---------------------------------------------------

jsi::Value invoke_bip32_fingerprint(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_bip32_fingerprint";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
  std::string curveStr = requireStringAt(rt, op, "curve", args, count, 2);
  uint8_t curveTag = curveTagFromString(curveStr);
  if (curveTag == 0xff) {
    throw jsi::JSError(rt, std::string(op) + ": unknown curve");
  }
  PathArg p = readPath(rt, op, path);

  ScrubbedSlot blob = loadSlotOrThrow(rt, op, alias);
  SlotView slot;
  parseSlot(blob.bytes.data(), blob.bytes.size(), slot);
  requireSlotKind(rt, op, slot, SlotKind::Bip32Seed);
  requireSeedPayloadLen(rt, op, slot);

  DerivedKey k;
  std::memset(&k, 0, sizeof(k));
  deriveFromSeed(
    rt, op, slot.payload, slot.payloadLen, curveTag, p.data, p.steps, k);
  uint32_t fp = k.fingerprint;
  memzero(&k, sizeof(k));
  return jsi::Value(static_cast<double>(fp));
}

// --- BIP-32: getPublicKey --------------------------------------------------

jsi::Value invoke_bip32_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_bip32_get_public";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
  std::string curveStr = requireStringAt(rt, op, "curve", args, count, 2);
  bool compact = requireBoolAt(rt, op, "compact", args, count, 3);
  uint8_t curveTag = curveTagFromString(curveStr);
  if (curveTag == 0xff) {
    throw jsi::JSError(rt, std::string(op) + ": unknown curve");
  }
  PathArg p = readPath(rt, op, path);

  ScrubbedSlot blob = loadSlotOrThrow(rt, op, alias);
  SlotView slot;
  parseSlot(blob.bytes.data(), blob.bytes.size(), slot);
  requireSlotKind(rt, op, slot, SlotKind::Bip32Seed);
  requireSeedPayloadLen(rt, op, slot);

  DerivedKey k;
  std::memset(&k, 0, sizeof(k));
  deriveFromSeed(
    rt, op, slot.payload, slot.payloadLen, curveTag, p.data, p.steps, k);

  std::vector<uint8_t> out;
  if (curveTag == kCurveTagEd25519) {
    // SLIP-10 ed25519 nodes carry public_key as 0x00 || ed25519_pub(32B).
    // For the compressed view we strip the leading 0x00; "uncompressed" is
    // not meaningful for Edwards curves so we always return 32 bytes.
    out.assign(k.pub + 1, k.pub + 33);
  } else if (compact) {
    out.assign(k.pub, k.pub + 33);
  } else {
    // Re-expand to 65 bytes via ecdsa_read_pubkey + bn_write_be.
    const ecdsa_curve* curve = ecdsaCurveFromTag(curveTag);
    curve_point point = {};
    if (ecdsa_read_pubkey(curve, k.pub, &point) == 0) {
      memzero(&point, sizeof(point));
      memzero(&k, sizeof(k));
      throw jsi::JSError(rt, std::string(op) + ": derived pubkey invalid");
    }
    out.resize(65);
    out[0] = 0x04;
    bn_write_be(&point.x, out.data() + 1);
    bn_write_be(&point.y, out.data() + 33);
    memzero(&point, sizeof(point));
  }

  memzero(&k, sizeof(k));
  return wrapDigest(rt, std::move(out));
}

// --- BIP-32: signEcdsa -----------------------------------------------------

jsi::Value invoke_bip32_sign_ecdsa(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_bip32_sign_ecdsa";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
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

  ScrubbedSlot blob = loadSlotOrThrow(rt, op, alias);
  SlotView slot;
  parseSlot(blob.bytes.data(), blob.bytes.size(), slot);
  requireSlotKind(rt, op, slot, SlotKind::Bip32Seed);
  requireSeedPayloadLen(rt, op, slot);

  DerivedKey k;
  std::memset(&k, 0, sizeof(k));
  deriveFromSeed(
    rt, op, slot.payload, slot.payloadLen, curveTag, p.data, p.steps, k);

  std::vector<uint8_t> out(65);
  uint8_t pby = 0;
  int err = ecdsa_sign_digest(
    curve, k.priv, digest.data(rt), out.data() + 1, &pby, nullptr);
  memzero(&k, sizeof(k));
  if (err != 0) {
    memzero(out.data(), out.size());
    throw jsi::JSError(rt, std::string(op) + ": signing failed");
  }
  out[0] = pby;
  return wrapDigest(rt, std::move(out));
}

// --- BIP-32: signSchnorr / signSchnorrTaproot ------------------------------

jsi::Value invoke_bip32_sign_schnorr_impl(
  jsi::Runtime& rt,
  const jsi::Value* args,
  size_t count,
  const char* op,
  bool taproot
) {
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
  auto digest = requireArrayBufferAt(rt, op, "digest", args, count, 2);
  if (digest.size(rt) != 32) {
    throw jsi::JSError(rt, std::string(op) + ": digest must be 32 bytes");
  }
  // Last optional arg: aux (for plain Schnorr) or merkleRoot (for Taproot).
  // null/undefined → empty.
  const uint8_t* extraPtr = nullptr;
  size_t extraLen = 0;
  if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
    auto extra = requireArrayBufferAt(
      rt, op, taproot ? "merkleRoot" : "aux", args, count, 3);
    extraPtr = extra.data(rt);
    extraLen = extra.size(rt);
    if (!taproot && extraLen != 32) {
      throw jsi::JSError(rt, std::string(op) + ": aux must be 32 bytes");
    }
  }
  PathArg p = readPath(rt, op, path);

  ScrubbedSlot blob = loadSlotOrThrow(rt, op, alias);
  SlotView slot;
  parseSlot(blob.bytes.data(), blob.bytes.size(), slot);
  requireSlotKind(rt, op, slot, SlotKind::Bip32Seed);
  requireSeedPayloadLen(rt, op, slot);

  DerivedKey k;
  std::memset(&k, 0, sizeof(k));
  deriveFromSeed(
    rt, op, slot.payload, slot.payloadLen, kCurveTagSecp256k1,
    p.data, p.steps, k);

  uint8_t signingPriv[32];
  if (taproot) {
    if (!schnorr_internal::tweakPrivate(
          k.priv, extraPtr, extraLen, signingPriv)) {
      memzero(&k, sizeof(k));
      memzero(signingPriv, sizeof(signingPriv));
      throw jsi::JSError(rt, std::string(op) + ": tap-tweak failed");
    }
  } else {
    std::memcpy(signingPriv, k.priv, 32);
  }
  memzero(&k, sizeof(k));

  std::vector<uint8_t> out(64);
  bool ok = schnorr_internal::sign(
    signingPriv, digest.data(rt),
    taproot ? nullptr : extraPtr,
    out.data());
  memzero(signingPriv, sizeof(signingPriv));
  if (!ok) {
    memzero(out.data(), out.size());
    throw jsi::JSError(rt, std::string(op) + ": signing failed");
  }
  return wrapDigest(rt, std::move(out));
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

// --- BIP-32: signEd25519 ---------------------------------------------------

jsi::Value invoke_bip32_sign_ed25519(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_bip32_sign_ed25519";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  auto path = requireArrayBufferAt(rt, op, "path", args, count, 1);
  auto msg = requireArrayBufferAt(rt, op, "msg", args, count, 2);
  PathArg p = readPath(rt, op, path);

  ScrubbedSlot blob = loadSlotOrThrow(rt, op, alias);
  SlotView slot;
  parseSlot(blob.bytes.data(), blob.bytes.size(), slot);
  requireSlotKind(rt, op, slot, SlotKind::Bip32Seed);
  requireSeedPayloadLen(rt, op, slot);

  DerivedKey k;
  std::memset(&k, 0, sizeof(k));
  deriveFromSeed(
    rt, op, slot.payload, slot.payloadLen, kCurveTagEd25519,
    p.data, p.steps, k);

  std::vector<uint8_t> out(64);
  ed25519_sign(safeData(rt, msg), msg.size(rt), k.priv, out.data());
  memzero(&k, sizeof(k));
  return wrapDigest(rt, std::move(out));
}

// --- BIP-32: ecdh ----------------------------------------------------------

jsi::Value invoke_bip32_ecdh(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_bip32_ecdh";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
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

  ScrubbedSlot blob = loadSlotOrThrow(rt, op, alias);
  SlotView slot;
  parseSlot(blob.bytes.data(), blob.bytes.size(), slot);
  requireSlotKind(rt, op, slot, SlotKind::Bip32Seed);
  requireSeedPayloadLen(rt, op, slot);

  DerivedKey k;
  std::memset(&k, 0, sizeof(k));
  deriveFromSeed(
    rt, op, slot.payload, slot.payloadLen, curveTag, p.data, p.steps, k);

  uint8_t full[65];
  int err = ecdh_multiply(curve, k.priv, pub.data(rt), full);
  memzero(&k, sizeof(k));
  if (err != 0) {
    memzero(full, sizeof(full));
    throw jsi::JSError(rt, std::string(op) + ": shared secret computation failed");
  }
  std::vector<uint8_t> out(33);
  out[0] = 0x02 | (full[64] & 0x01);
  std::memcpy(out.data() + 1, full + 1, 32);
  memzero(full, sizeof(full));
  return wrapDigest(rt, std::move(out));
}

// --- RAW: setPrivate -------------------------------------------------------

jsi::Value invoke_raw_set_private(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_raw_set_private";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
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
  auto wrapped = wrapRawSlot(curveTag, priv.data(rt));
  try {
    SecureKVBackend::set(alias, wrapped.data(), wrapped.size());
  } catch (const std::exception& e) {
    memzero(wrapped.data(), wrapped.size());
    rethrowAsJsi(rt, op, e);
  }
  memzero(wrapped.data(), wrapped.size());
  return jsi::Value::undefined();
}

// Helper: parse RAW slot, copy into RawKey, optionally enforce a curve.
struct RawKey {
  uint8_t curveTag;
  uint8_t priv[32];
};

void loadRawKey(
  jsi::Runtime& rt,
  const char* op,
  const std::string& alias,
  RawKey& out,
  int requiredCurveTag /* -1 = any */
) {
  ScrubbedSlot blob = loadSlotOrThrow(rt, op, alias);
  SlotView slot;
  parseSlot(blob.bytes.data(), blob.bytes.size(), slot);
  requireSlotKind(rt, op, slot, SlotKind::RawPrivate);
  requirePayloadLen(rt, op, slot, kRawPayloadLen);

  out.curveTag = slot.payload[0];
  std::memcpy(out.priv, slot.payload + 1, 32);

  if (requiredCurveTag >= 0 &&
      out.curveTag != static_cast<uint8_t>(requiredCurveTag)) {
    memzero(&out, sizeof(out));
    throw jsi::JSError(
      rt,
      std::string(op) + ": slot curve is " +
        (curveNameFromTag(out.curveTag) ? curveNameFromTag(out.curveTag) : "unknown") +
        ", expected " +
        (curveNameFromTag(static_cast<uint8_t>(requiredCurveTag)) ?
           curveNameFromTag(static_cast<uint8_t>(requiredCurveTag)) : "unknown"));
  }
}

// --- RAW: getPublicKey -----------------------------------------------------

jsi::Value invoke_raw_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_raw_get_public";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  bool compact = requireBoolAt(rt, op, "compact", args, count, 1);

  RawKey k;
  loadRawKey(rt, op, alias, k, -1);

  std::vector<uint8_t> out;
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
      throw jsi::JSError(rt, std::string(op) + ": invalid private key");
    }
  }
  memzero(&k, sizeof(k));
  return wrapDigest(rt, std::move(out));
}

// --- RAW: signEcdsa --------------------------------------------------------

jsi::Value invoke_raw_sign_ecdsa(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_raw_sign_ecdsa";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  auto digest = requireArrayBufferAt(rt, op, "digest", args, count, 1);
  if (digest.size(rt) != 32) {
    throw jsi::JSError(rt, std::string(op) + ": digest must be 32 bytes");
  }

  RawKey k;
  loadRawKey(rt, op, alias, k, -1);
  if (k.curveTag != kCurveTagSecp256k1 &&
      k.curveTag != kCurveTagNist256p1) {
    memzero(&k, sizeof(k));
    throw jsi::JSError(
      rt, std::string(op) + ": ECDSA requires secp256k1 or nist256p1 slot");
  }
  const ecdsa_curve* curve = ecdsaCurveFromTag(k.curveTag);

  std::vector<uint8_t> out(65);
  uint8_t pby = 0;
  int err = ecdsa_sign_digest(
    curve, k.priv, digest.data(rt), out.data() + 1, &pby, nullptr);
  memzero(&k, sizeof(k));
  if (err != 0) {
    memzero(out.data(), out.size());
    throw jsi::JSError(rt, std::string(op) + ": signing failed");
  }
  out[0] = pby;
  return wrapDigest(rt, std::move(out));
}

// --- RAW: signSchnorr / signSchnorrTaproot ---------------------------------

jsi::Value invoke_raw_sign_schnorr_impl(
  jsi::Runtime& rt,
  const jsi::Value* args,
  size_t count,
  const char* op,
  bool taproot
) {
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  auto digest = requireArrayBufferAt(rt, op, "digest", args, count, 1);
  if (digest.size(rt) != 32) {
    throw jsi::JSError(rt, std::string(op) + ": digest must be 32 bytes");
  }
  const uint8_t* extraPtr = nullptr;
  size_t extraLen = 0;
  if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
    auto extra = requireArrayBufferAt(
      rt, op, taproot ? "merkleRoot" : "aux", args, count, 2);
    extraPtr = extra.data(rt);
    extraLen = extra.size(rt);
    if (!taproot && extraLen != 32) {
      throw jsi::JSError(rt, std::string(op) + ": aux must be 32 bytes");
    }
  }

  RawKey k;
  loadRawKey(rt, op, alias, k, kCurveTagSecp256k1);

  uint8_t signingPriv[32];
  if (taproot) {
    if (!schnorr_internal::tweakPrivate(
          k.priv, extraPtr, extraLen, signingPriv)) {
      memzero(&k, sizeof(k));
      memzero(signingPriv, sizeof(signingPriv));
      throw jsi::JSError(rt, std::string(op) + ": tap-tweak failed");
    }
  } else {
    std::memcpy(signingPriv, k.priv, 32);
  }
  memzero(&k, sizeof(k));

  std::vector<uint8_t> out(64);
  bool ok = schnorr_internal::sign(
    signingPriv, digest.data(rt),
    taproot ? nullptr : extraPtr,
    out.data());
  memzero(signingPriv, sizeof(signingPriv));
  if (!ok) {
    memzero(out.data(), out.size());
    throw jsi::JSError(rt, std::string(op) + ": signing failed");
  }
  return wrapDigest(rt, std::move(out));
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

// --- RAW: signEd25519 ------------------------------------------------------

jsi::Value invoke_raw_sign_ed25519(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_raw_sign_ed25519";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  auto msg = requireArrayBufferAt(rt, op, "msg", args, count, 1);

  RawKey k;
  loadRawKey(rt, op, alias, k, kCurveTagEd25519);

  std::vector<uint8_t> out(64);
  ed25519_sign(safeData(rt, msg), msg.size(rt), k.priv, out.data());
  memzero(&k, sizeof(k));
  return wrapDigest(rt, std::move(out));
}

// --- RAW: ecdh -------------------------------------------------------------

jsi::Value invoke_raw_ecdh(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  const char* op = "secure_kv_raw_ecdh";
  std::string alias = requireStringAt(rt, op, "key", args, count, 0);
  requireValidAlias(rt, op, alias);
  auto pub = requireArrayBufferAt(rt, op, "peerPub", args, count, 1);
  size_t publen = pub.size(rt);
  if (publen != 33 && publen != 65) {
    throw jsi::JSError(rt, std::string(op) + ": peerPub must be 33 or 65 bytes");
  }

  RawKey k;
  loadRawKey(rt, op, alias, k, -1);
  if (k.curveTag != kCurveTagSecp256k1 &&
      k.curveTag != kCurveTagNist256p1) {
    memzero(&k, sizeof(k));
    throw jsi::JSError(
      rt, std::string(op) + ": ECDH requires secp256k1 or nist256p1 slot");
  }
  const ecdsa_curve* curve = ecdsaCurveFromTag(k.curveTag);

  uint8_t full[65];
  int err = ecdh_multiply(curve, k.priv, pub.data(rt), full);
  memzero(&k, sizeof(k));
  if (err != 0) {
    memzero(full, sizeof(full));
    throw jsi::JSError(rt, std::string(op) + ": shared secret computation failed");
  }
  std::vector<uint8_t> out(33);
  out[0] = 0x02 | (full[64] & 0x01);
  std::memcpy(out.data() + 1, full + 1, 32);
  memzero(full, sizeof(full));
  return wrapDigest(rt, std::move(out));
}

}  // namespace

void registerSecureKVSignMethods(MethodMap& map) {
  // BIP-32 / SLIP-10 derivation on a stored seed
  map.push_back({"secure_kv_bip32_set_seed",            2, invoke_bip32_set_seed});
  map.push_back({"secure_kv_bip32_fingerprint",         3, invoke_bip32_fingerprint});
  map.push_back({"secure_kv_bip32_get_public",          4, invoke_bip32_get_public});
  map.push_back({"secure_kv_bip32_sign_ecdsa",          4, invoke_bip32_sign_ecdsa});
  map.push_back({"secure_kv_bip32_sign_schnorr",        4, invoke_bip32_sign_schnorr});
  map.push_back({"secure_kv_bip32_sign_schnorr_taproot",4, invoke_bip32_sign_schnorr_taproot});
  map.push_back({"secure_kv_bip32_sign_ed25519",        3, invoke_bip32_sign_ed25519});
  map.push_back({"secure_kv_bip32_ecdh",                4, invoke_bip32_ecdh});

  // Raw 32-byte private key without derivation
  map.push_back({"secure_kv_raw_set_private",           3, invoke_raw_set_private});
  map.push_back({"secure_kv_raw_get_public",            2, invoke_raw_get_public});
  map.push_back({"secure_kv_raw_sign_ecdsa",            2, invoke_raw_sign_ecdsa});
  map.push_back({"secure_kv_raw_sign_schnorr",          3, invoke_raw_sign_schnorr});
  map.push_back({"secure_kv_raw_sign_schnorr_taproot",  3, invoke_raw_sign_schnorr_taproot});
  map.push_back({"secure_kv_raw_sign_ed25519",          2, invoke_raw_sign_ed25519});
  map.push_back({"secure_kv_raw_ecdh",                  2, invoke_raw_ecdh});
}

}  // namespace facebook::react::cryptolib

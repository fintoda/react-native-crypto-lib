#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

// Slot format used by every SecureKV blob.
//
//   [ 0]  tag (1 byte)
//   [1..] payload (variable, depends on tag)
//
// 0x00 — Blob: opaque user bytes via secureKV.set(). Payload = user data.
// 0x01 — Bip32Seed: BIP-32 / SLIP-10 seed for derivation. Payload = 16..64
//        bytes (BIP-32 spec range; bip39.toSeed produces 64).
// 0x02 — RawPrivate: a single 32-byte private scalar with curve binding.
//        Payload = [1B curve_tag][32B priv]. curve_tag = 0=secp256k1,
//        1=nist256p1, 2=ed25519. The curve is fixed at provisioning time
//        so sign-side methods can reject mismatches before touching crypto.
// 0x03 — PassphraseWrapped: a passphrase-encrypted envelope holding one
//        of the above slot kinds. Payload = [1B version][4B iters BE]
//        [16B salt][12B IV][16B verifier][AES-GCM ciphertext+16B tag].
//        See cpp/SecureKVPassphrase.h for envelope format and the
//        wrap/unwrap helpers.
//
// This header is the single source of truth for the format; both
// cpp/SecureKV.cpp (set/get/has/list/clear/delete) and cpp/SecureKVSign.cpp
// (bip32/raw signing) include it.

namespace facebook::react::cryptolib {

enum class SlotKind : uint8_t {
  Blob = 0x00,
  Bip32Seed = 0x01,
  RawPrivate = 0x02,
  PassphraseWrapped = 0x03,
};

// BIP-32 / SLIP-10 accept seeds of 128 to 512 bits. We mirror that
// here rather than fixing on bip39.toSeed's 64-byte output so callers
// can also store smaller seeds (e.g. BIP-32 reference vectors, raw
// entropy from a hardware wallet, etc.).
constexpr size_t kMinSeedPayloadLen = 16;
constexpr size_t kMaxSeedPayloadLen = 64;
constexpr size_t kRawPayloadLen = 1 /*curve_tag*/ + 32 /*priv*/;

constexpr uint8_t kCurveTagSecp256k1 = 0;
constexpr uint8_t kCurveTagNist256p1 = 1;
constexpr uint8_t kCurveTagEd25519 = 2;

inline const char* slotKindName(SlotKind k) {
  switch (k) {
    case SlotKind::Blob: return "BLOB";
    case SlotKind::Bip32Seed: return "SEED";
    case SlotKind::RawPrivate: return "RAW";
    case SlotKind::PassphraseWrapped: return "WRAPPED";
  }
  return "UNKNOWN";
}

inline std::vector<uint8_t> wrapBlobSlot(const uint8_t* data, size_t len) {
  std::vector<uint8_t> out(len + 1);
  out[0] = static_cast<uint8_t>(SlotKind::Blob);
  if (len > 0) std::memcpy(out.data() + 1, data, len);
  return out;
}

inline std::vector<uint8_t> wrapSeedSlot(
  const uint8_t* seed, size_t len
) {
  std::vector<uint8_t> out(len + 1);
  out[0] = static_cast<uint8_t>(SlotKind::Bip32Seed);
  std::memcpy(out.data() + 1, seed, len);
  return out;
}

inline std::vector<uint8_t> wrapRawSlot(uint8_t curveTag, const uint8_t priv32[32]) {
  std::vector<uint8_t> out(1 + kRawPayloadLen);
  out[0] = static_cast<uint8_t>(SlotKind::RawPrivate);
  out[1] = curveTag;
  std::memcpy(out.data() + 2, priv32, 32);
  return out;
}

struct SlotView {
  SlotKind kind = SlotKind::Blob;
  const uint8_t* payload = nullptr;
  size_t payloadLen = 0;
};

// Returns false on a zero-length blob (no tag byte). The payload pointer
// references the original buffer — caller must keep the source alive.
inline bool parseSlot(const uint8_t* data, size_t len, SlotView& out) {
  if (len < 1) return false;
  out.kind = static_cast<SlotKind>(data[0]);
  out.payload = data + 1;
  out.payloadLen = len - 1;
  return true;
}

}  // namespace facebook::react::cryptolib

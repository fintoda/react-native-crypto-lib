// BIP-32 / SLIP-10 HD key derivation over secp256k1, nist256p1 and
// ed25519 (SLIP-10 variant). We serialize HDNode state as a fixed 108-byte
// binary blob across the JSI boundary so every derive call is a single
// stateless hop — no handles / finalizers on the JS side.
//
// Binary layout (108 bytes, all integers big-endian):
//
//   [ 0]      curve_tag       u8   0=secp256k1, 1=nist256p1, 2=ed25519
//   [ 1]      has_private     u8   0 or 1
//   [ 2]      depth           u8
//   [ 3..6]   parent_fp       u32  parent fingerprint
//   [ 7..10]  child_num       u32
//   [11..42]  chain_code      32B
//   [43..74]  private_key     32B  zeroed when has_private == 0
//   [75..107] public_key      33B  always populated (compressed or x-only+tag)
//
// parent_fp for a freshly-generated master node is 0. For derived nodes
// we compute it via hdnode_fingerprint(parent) just before the last
// child derivation.

#include "Common.h"

#include <cstring>

extern "C" {
#include "bip32.h"
#include "curves.h"
#include "memzero.h"
}

namespace facebook::react::cryptolib {
namespace {

constexpr size_t kNodeSize = 108;
constexpr size_t kChainCodeOffset = 11;
constexpr size_t kPrivateKeyOffset = 43;
constexpr size_t kPublicKeyOffset = 75;

const char* curveNameFromTag(uint8_t tag) {
  switch (tag) {
    case 0: return SECP256K1_NAME;
    case 1: return NIST256P1_NAME;
    case 2: return ED25519_NAME;
    default: return nullptr;
  }
}

uint8_t curveTagFromName(const std::string& name) {
  if (name == "secp256k1") return 0;
  if (name == "nist256p1") return 1;
  if (name == "ed25519") return 2;
  return 0xff;
}

void writeBeU32(uint8_t* dst, uint32_t v) {
  dst[0] = static_cast<uint8_t>(v >> 24);
  dst[1] = static_cast<uint8_t>(v >> 16);
  dst[2] = static_cast<uint8_t>(v >> 8);
  dst[3] = static_cast<uint8_t>(v);
}

uint32_t readBeU32(const uint8_t* src) {
  return (static_cast<uint32_t>(src[0]) << 24) |
         (static_cast<uint32_t>(src[1]) << 16) |
         (static_cast<uint32_t>(src[2]) << 8) |
         static_cast<uint32_t>(src[3]);
}

// Pack a trezor HDNode + its parent fingerprint into our binary layout.
void packNode(
  uint8_t tag,
  uint8_t hasPrivate,
  uint32_t parentFp,
  const HDNode& node,
  uint8_t out[kNodeSize]
) {
  std::memset(out, 0, kNodeSize);
  out[0] = tag;
  out[1] = hasPrivate;
  out[2] = static_cast<uint8_t>(node.depth);
  writeBeU32(out + 3, parentFp);
  writeBeU32(out + 7, node.child_num);
  std::memcpy(out + kChainCodeOffset, node.chain_code, 32);
  if (hasPrivate) {
    std::memcpy(out + kPrivateKeyOffset, node.private_key, 32);
  }
  std::memcpy(out + kPublicKeyOffset, node.public_key, 33);
}

// Inverse of packNode: restore an HDNode from our binary blob. Returns
// false if the curve tag is unknown.
bool unpackNode(
  const uint8_t* in,
  size_t len,
  HDNode& out,
  uint8_t& tagOut,
  uint8_t& hasPrivateOut,
  uint32_t& parentFpOut
) {
  if (len != kNodeSize) return false;
  tagOut = in[0];
  hasPrivateOut = in[1];
  const char* curveName = curveNameFromTag(tagOut);
  if (!curveName) return false;

  std::memset(&out, 0, sizeof(out));
  out.curve = get_curve_by_name(curveName);
  if (!out.curve) return false;
  out.depth = in[2];
  parentFpOut = readBeU32(in + 3);
  out.child_num = readBeU32(in + 7);
  std::memcpy(out.chain_code, in + kChainCodeOffset, 32);
  if (hasPrivateOut) {
    std::memcpy(out.private_key, in + kPrivateKeyOffset, 32);
  }
  std::memcpy(out.public_key, in + kPublicKeyOffset, 33);
  // public key is considered set iff the leading byte is non-zero; SLIP-10
  // ed25519 nodes carry a 0x00-prefixed 32-byte x key so the byte is 0 and
  // we treat that as "needs recompute" on the trezor side too.
  out.is_public_key_set = out.public_key[0] != 0 || hasPrivateOut == 0;
  return true;
}

// --- bindings --------------------------------------------------------------

jsi::Value invoke_bip32_from_seed(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto seed = requireArrayBufferAt(rt, "bip32_from_seed", "seed", args, count, 0);
  auto curve = requireStringAt(rt, "bip32_from_seed", "curve", args, count, 1);
  uint8_t tag = curveTagFromName(curve);
  if (tag == 0xff) {
    throw jsi::JSError(rt, "bip32_from_seed: unknown curve");
  }
  HDNode node;
  std::memset(&node, 0, sizeof(node));
  int rc = hdnode_from_seed(
    seed.data(rt), static_cast<int>(seed.size(rt)), curveNameFromTag(tag), &node);
  if (rc != 1) {
    memzero(&node, sizeof(node));
    throw jsi::JSError(rt, "bip32_from_seed: seed rejected");
  }
  // Force public-key materialisation so the serialized blob always carries
  // a valid pub field (callers can then derive without another hdnode call).
  hdnode_fill_public_key(&node);

  std::vector<uint8_t> out(kNodeSize);
  packNode(tag, /*hasPrivate*/ 1, /*parentFp*/ 0, node, out.data());
  memzero(&node, sizeof(node));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_bip32_derive(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto nodeBuf = requireArrayBufferAt(rt, "bip32_derive", "node", args, count, 0);
  auto path = requireArrayBufferAt(rt, "bip32_derive", "path", args, count, 1);

  size_t pathLen = path.size(rt);
  if (pathLen % 4 != 0) {
    throw jsi::JSError(rt, "bip32_derive: path must be a multiple of 4 bytes");
  }
  size_t steps = pathLen / 4;

  HDNode node;
  uint8_t tag = 0, hasPriv = 0;
  uint32_t parentFp = 0;
  if (!unpackNode(nodeBuf.data(rt), nodeBuf.size(rt), node, tag, hasPriv, parentFp)) {
    throw jsi::JSError(rt, "bip32_derive: invalid node");
  }
  if (!hasPriv) {
    memzero(&node, sizeof(node));
    throw jsi::JSError(
      rt, "bip32_derive: private derivation requires a private key");
  }

  const uint8_t* pathBytes = path.data(rt);
  uint32_t currentFp = parentFp;
  for (size_t k = 0; k < steps; k++) {
    uint32_t index = readBeU32(pathBytes + k * 4);
    // Parent fingerprint = fingerprint of this node *before* we descend
    // into the last child, so we snapshot on every step.
    currentFp = hdnode_fingerprint(&node);
    if (hdnode_private_ckd(&node, index) != 1) {
      memzero(&node, sizeof(node));
      throw jsi::JSError(rt, "bip32_derive: derivation failed");
    }
  }
  hdnode_fill_public_key(&node);

  std::vector<uint8_t> out(kNodeSize);
  packNode(tag, /*hasPrivate*/ 1, steps == 0 ? parentFp : currentFp, node, out.data());
  memzero(&node, sizeof(node));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_bip32_derive_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto nodeBuf = requireArrayBufferAt(rt, "bip32_derive_public", "node", args, count, 0);
  auto path = requireArrayBufferAt(rt, "bip32_derive_public", "path", args, count, 1);

  size_t pathLen = path.size(rt);
  if (pathLen % 4 != 0) {
    throw jsi::JSError(rt, "bip32_derive_public: path must be a multiple of 4 bytes");
  }
  size_t steps = pathLen / 4;

  HDNode node;
  uint8_t tag = 0, hasPriv = 0;
  uint32_t parentFp = 0;
  if (!unpackNode(nodeBuf.data(rt), nodeBuf.size(rt), node, tag, hasPriv, parentFp)) {
    throw jsi::JSError(rt, "bip32_derive_public: invalid node");
  }
  // Public CKD does not accept hardened children. Also: ed25519 SLIP-10
  // doesn't support public derivation at all — trezor's hdnode_public_ckd
  // rejects it internally.

  const uint8_t* pathBytes = path.data(rt);
  uint32_t currentFp = parentFp;
  for (size_t k = 0; k < steps; k++) {
    uint32_t index = readBeU32(pathBytes + k * 4);
    if (index & 0x80000000u) {
      memzero(&node, sizeof(node));
      throw jsi::JSError(
        rt, "bip32_derive_public: hardened index requires a private key");
    }
    currentFp = hdnode_fingerprint(&node);
    if (hdnode_public_ckd(&node, index) != 1) {
      memzero(&node, sizeof(node));
      throw jsi::JSError(rt, "bip32_derive_public: derivation failed");
    }
  }

  std::vector<uint8_t> out(kNodeSize);
  // Output is always neutered regardless of the input carrying a priv key.
  packNode(tag, /*hasPrivate*/ 0, steps == 0 ? parentFp : currentFp, node, out.data());
  memzero(&node, sizeof(node));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_bip32_serialize(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto nodeBuf = requireArrayBufferAt(rt, "bip32_serialize", "node", args, count, 0);
  double version =
    requireIntAt(rt, "bip32_serialize", "version", args, count, 1, 0, 0xffffffff);
  bool isPrivate =
    requireBoolAt(rt, "bip32_serialize", "private", args, count, 2);

  HDNode node;
  uint8_t tag = 0, hasPriv = 0;
  uint32_t parentFp = 0;
  if (!unpackNode(nodeBuf.data(rt), nodeBuf.size(rt), node, tag, hasPriv, parentFp)) {
    throw jsi::JSError(rt, "bip32_serialize: invalid node");
  }
  if (isPrivate && !hasPriv) {
    memzero(&node, sizeof(node));
    throw jsi::JSError(
      rt, "bip32_serialize: cannot serialize xprv without a private key");
  }
  char out[XPUB_MAXLEN];
  int rc = isPrivate
    ? hdnode_serialize_private(
        &node, parentFp, static_cast<uint32_t>(version), out, sizeof(out))
    : hdnode_serialize_public(
        &node, parentFp, static_cast<uint32_t>(version), out, sizeof(out));
  memzero(&node, sizeof(node));
  if (rc <= 0) {
    throw jsi::JSError(rt, "bip32_serialize: encoding failed");
  }
  return jsi::String::createFromUtf8(rt, std::string(out, rc - 1));
}

jsi::Value invoke_bip32_deserialize(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto str = requireStringAt(rt, "bip32_deserialize", "str", args, count, 0);
  double version =
    requireIntAt(rt, "bip32_deserialize", "version", args, count, 1, 0, 0xffffffff);
  auto curve = requireStringAt(rt, "bip32_deserialize", "curve", args, count, 2);
  bool isPrivate =
    requireBoolAt(rt, "bip32_deserialize", "private", args, count, 3);

  uint8_t tag = curveTagFromName(curve);
  if (tag == 0xff) {
    throw jsi::JSError(rt, "bip32_deserialize: unknown curve");
  }
  HDNode node;
  uint32_t parentFp = 0;
  int rc = isPrivate
    ? hdnode_deserialize_private(
        str.c_str(), static_cast<uint32_t>(version),
        curveNameFromTag(tag), &node, &parentFp)
    : hdnode_deserialize_public(
        str.c_str(), static_cast<uint32_t>(version),
        curveNameFromTag(tag), &node, &parentFp);
  if (rc != 0) {
    memzero(&node, sizeof(node));
    throw jsi::JSError(rt, "bip32_deserialize: decoding failed");
  }
  if (isPrivate) hdnode_fill_public_key(&node);

  std::vector<uint8_t> out(kNodeSize);
  packNode(tag, isPrivate ? 1 : 0, parentFp, node, out.data());
  memzero(&node, sizeof(node));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_bip32_fingerprint(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto nodeBuf = requireArrayBuffer(rt, "bip32_fingerprint", args, count);
  HDNode node;
  uint8_t tag = 0, hasPriv = 0;
  uint32_t parentFp = 0;
  if (!unpackNode(nodeBuf.data(rt), nodeBuf.size(rt), node, tag, hasPriv, parentFp)) {
    throw jsi::JSError(rt, "bip32_fingerprint: invalid node");
  }
  uint32_t fp = hdnode_fingerprint(&node);
  memzero(&node, sizeof(node));
  return jsi::Value(static_cast<double>(fp));
}

} // namespace

void registerBip32Methods(MethodMap& map) {
  map.push_back({"bip32_from_seed",      2, invoke_bip32_from_seed});
  map.push_back({"bip32_derive",         2, invoke_bip32_derive});
  map.push_back({"bip32_derive_public",  2, invoke_bip32_derive_public});
  map.push_back({"bip32_serialize",      3, invoke_bip32_serialize});
  map.push_back({"bip32_deserialize",    4, invoke_bip32_deserialize});
  map.push_back({"bip32_fingerprint",    1, invoke_bip32_fingerprint});
}

}

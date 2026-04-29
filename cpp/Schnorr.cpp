// Schnorr / BIP-340 ----------------------------------------------------------
// trezor-crypto ships BIP-340 only via zkp_bip340.c, which pulls in the
// full libsecp256k1-zkp submodule. We don't want that dependency, so we
// implement BIP-340 directly on top of the bignum / point primitives we
// already have. The actual sign / verify / tweak primitives live in
// cpp/SchnorrInternal.h so cpp/SecureKVSign.cpp can reuse them without
// either duplicating the algorithms or returning private keys to JS.

#include "Common.h"
#include "SchnorrInternal.h"

namespace facebook::react::cryptolib {
namespace {

namespace schnorr = schnorr_internal;

jsi::Value invoke_schnorr_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBuffer(rt, "schnorr_get_public", args, count);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "schnorr_get_public: priv must be 32 bytes");
  }
  std::vector<uint8_t> out(32);
  if (!schnorr::getPublicX(priv.data(rt), out.data())) {
    throw jsi::JSError(rt, "schnorr_get_public: invalid private key");
  }
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_schnorr_verify_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pub = requireArrayBuffer(rt, "schnorr_verify_public", args, count);
  if (pub.size(rt) != 32) return jsi::Value(false);
  return jsi::Value(schnorr::verifyPublicX(pub.data(rt)));
}

jsi::Value invoke_schnorr_sign(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBufferAt(rt, "schnorr_sign", "priv", args, count, 0);
  auto digest = requireArrayBufferAt(rt, "schnorr_sign", "digest", args, count, 1);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "schnorr_sign: priv must be 32 bytes");
  }
  if (digest.size(rt) != 32) {
    throw jsi::JSError(rt, "schnorr_sign: digest must be 32 bytes");
  }
  // Optional 32-byte aux_rand. Allowed: undefined/null → zeroed aux.
  const uint8_t* auxPtr = nullptr;
  if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
    auto aux = requireArrayBufferAt(rt, "schnorr_sign", "aux", args, count, 2);
    if (aux.size(rt) != 32) {
      throw jsi::JSError(rt, "schnorr_sign: aux must be 32 bytes");
    }
    auxPtr = aux.data(rt);
  }
  std::vector<uint8_t> out(64);
  if (!schnorr::sign(priv.data(rt), digest.data(rt), auxPtr, out.data())) {
    throw jsi::JSError(rt, "schnorr_sign: signing failed");
  }
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_schnorr_verify(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pub = requireArrayBufferAt(rt, "schnorr_verify", "pub", args, count, 0);
  auto sig = requireArrayBufferAt(rt, "schnorr_verify", "sig", args, count, 1);
  auto digest = requireArrayBufferAt(rt, "schnorr_verify", "digest", args, count, 2);
  if (pub.size(rt) != 32 || sig.size(rt) != 64 || digest.size(rt) != 32) {
    return jsi::Value(false);
  }
  return jsi::Value(
    schnorr::verify(pub.data(rt), sig.data(rt), digest.data(rt)));
}

jsi::Value invoke_schnorr_tweak_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pub = requireArrayBufferAt(rt, "schnorr_tweak_public", "pub", args, count, 0);
  if (pub.size(rt) != 32) {
    throw jsi::JSError(rt, "schnorr_tweak_public: pub must be 32 bytes");
  }
  // Optional merkle root — undefined/null → empty.
  const uint8_t* rootPtr = nullptr;
  size_t rootLen = 0;
  if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
    auto root = requireArrayBufferAt(rt, "schnorr_tweak_public", "root", args, count, 1);
    rootPtr = root.data(rt);
    rootLen = root.size(rt);
  }
  // Output shape: 33 bytes = 32-byte tweaked x || 1-byte parity (0 or 1).
  std::vector<uint8_t> out(33);
  int parity = 0;
  if (!schnorr::tweakPublic(pub.data(rt), rootPtr, rootLen, out.data(), &parity)) {
    throw jsi::JSError(rt, "schnorr_tweak_public: tweak failed");
  }
  out[32] = static_cast<uint8_t>(parity);
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_schnorr_tweak_private(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBufferAt(rt, "schnorr_tweak_private", "priv", args, count, 0);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "schnorr_tweak_private: priv must be 32 bytes");
  }
  const uint8_t* rootPtr = nullptr;
  size_t rootLen = 0;
  if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
    auto root = requireArrayBufferAt(rt, "schnorr_tweak_private", "root", args, count, 1);
    rootPtr = root.data(rt);
    rootLen = root.size(rt);
  }
  std::vector<uint8_t> out(32);
  if (!schnorr::tweakPrivate(priv.data(rt), rootPtr, rootLen, out.data())) {
    throw jsi::JSError(rt, "schnorr_tweak_private: tweak failed");
  }
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerSchnorrMethods(MethodMap& map) {
  map.push_back({"schnorr_get_public",    1, invoke_schnorr_get_public});
  map.push_back({"schnorr_verify_public", 1, invoke_schnorr_verify_public});
  map.push_back({"schnorr_sign",          3, invoke_schnorr_sign});
  map.push_back({"schnorr_verify",        3, invoke_schnorr_verify});
  map.push_back({"schnorr_tweak_public",  2, invoke_schnorr_tweak_public});
  map.push_back({"schnorr_tweak_private", 2, invoke_schnorr_tweak_private});
}

}

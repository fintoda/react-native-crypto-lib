#include "Common.h"

extern "C" {
#include "ed25519.h"
#include "memzero.h"
}

namespace facebook::react::cryptolib {
namespace {

// Ed25519 on 32-byte seeds. Unlike ECDSA, signing takes an arbitrary-
// length message (not a digest) — the internal hash is part of the
// scheme. trezor ships the donna implementation under ed25519-donna/.

jsi::Value invoke_ed25519_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBuffer(rt, "ed25519_get_public", args, count);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "ed25519_get_public: priv must be 32 bytes");
  }
  std::vector<uint8_t> out(32);
  ed25519_publickey(priv.data(rt), out.data());
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ed25519_sign(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBufferAt(rt, "ed25519_sign", "priv", args, count, 0);
  auto msg  = requireArrayBufferAt(rt, "ed25519_sign", "msg",  args, count, 1);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "ed25519_sign: priv must be 32 bytes");
  }
  // donna needs the public key to sign. We derive it here so the JS
  // surface stays symmetric with ecdsa.sign(priv, msg).
  ed25519_public_key pub;
  ed25519_publickey(priv.data(rt), pub);
  std::vector<uint8_t> out(64);
  ed25519_sign(safeData(rt, msg), msg.size(rt), priv.data(rt), out.data());
  memzero(pub, sizeof(pub));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ed25519_verify(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pub = requireArrayBufferAt(rt, "ed25519_verify", "pub", args, count, 0);
  auto sig = requireArrayBufferAt(rt, "ed25519_verify", "sig", args, count, 1);
  auto msg = requireArrayBufferAt(rt, "ed25519_verify", "msg", args, count, 2);
  if (pub.size(rt) != 32 || sig.size(rt) != 64) return jsi::Value(false);
  // ed25519_sign_open returns 0 on success, non-zero on failure.
  bool ok = ed25519_sign_open(
    safeData(rt, msg), msg.size(rt), pub.data(rt), sig.data(rt)) == 0;
  return jsi::Value(ok);
}

jsi::Value invoke_x25519_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBuffer(rt, "x25519_get_public", args, count);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "x25519_get_public: priv must be 32 bytes");
  }
  std::vector<uint8_t> out(32);
  curve25519_scalarmult_basepoint(out.data(), priv.data(rt));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_x25519_scalarmult(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBufferAt(rt, "x25519_scalarmult", "priv", args, count, 0);
  auto pub  = requireArrayBufferAt(rt, "x25519_scalarmult", "pub",  args, count, 1);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "x25519_scalarmult: priv must be 32 bytes");
  }
  if (pub.size(rt) != 32) {
    throw jsi::JSError(rt, "x25519_scalarmult: pub must be 32 bytes");
  }
  std::vector<uint8_t> out(32);
  curve25519_scalarmult(out.data(), priv.data(rt), pub.data(rt));
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerEd25519Methods(MethodMap& map) {
  map.push_back({"ed25519_get_public", 1, invoke_ed25519_get_public});
  map.push_back({"ed25519_sign",       2, invoke_ed25519_sign});
  map.push_back({"ed25519_verify",     3, invoke_ed25519_verify});
  map.push_back({"x25519_get_public",  1, invoke_x25519_get_public});
  map.push_back({"x25519_scalarmult",  2, invoke_x25519_scalarmult});
}

}

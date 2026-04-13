#include "Common.h"

#include <cstdlib>
#include <cstring>

extern "C" {
#include "ecdsa.h"
#include "memzero.h"
#include "nist256p1.h"
#include "secp256k1.h"

// trezor's ecdsa.c picks a nonce via random32() -> random_buffer() as a
// side-channel countermeasure. Provide our own implementation backed by
// arc4random_buf so we don't have to pull in trezor's rand.c (which has
// its own platform-specific fallbacks).
void random_buffer(uint8_t* buf, size_t len) {
  if (len) {
    arc4random_buf(buf, len);
  }
}
}

namespace facebook::react::cryptolib {
namespace {

const ecdsa_curve* resolveCurve(
  jsi::Runtime& rt,
  const char* methodName,
  const jsi::Value* args,
  size_t count
) {
  auto name = requireStringAt(rt, methodName, "curve", args, count, 0);
  if (name == "secp256k1") return &secp256k1;
  if (name == "nist256p1") return &nist256p1;
  throw jsi::JSError(
    rt,
    std::string(methodName) + ": unknown curve \"" + name + "\"");
}

jsi::Value invoke_ecdsa_random_private(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_random_private", args, count);
  std::vector<uint8_t> out(32);
  // Rejection sampling in [1, n-1]. For secp256k1 and nist256p1 the
  // probability of rejection per draw is ~2^-128, so one pass is enough
  // in practice — we still loop to be safe.
  for (int i = 0; i < 16; i++) {
    arc4random_buf(out.data(), out.size());
    // Delegate the range check to trezor: reading BE and comparing to
    // curve->order gives us exactly "0 < k < n".
    // (ecdsa.c doesn't export this, but we replicate the check cheaply:
    //  a value is valid iff ecdsa_get_public_key33 succeeds.)
    uint8_t probe[33];
    if (ecdsa_get_public_key33(curve, out.data(), probe) == 0) {
      memzero(probe, sizeof(probe));
      return wrapDigest(rt, std::move(out));
    }
  }
  memzero(out.data(), out.size());
  throw jsi::JSError(rt, "ecdsa_random_private: entropy source failed");
}

jsi::Value invoke_ecdsa_validate_private(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_validate_private", args, count);
  auto priv = requireArrayBufferAt(rt, "ecdsa_validate_private", "priv", args, count, 1);
  if (priv.size(rt) != 32) return jsi::Value(false);
  uint8_t probe[33];
  bool ok = ecdsa_get_public_key33(curve, priv.data(rt), probe) == 0;
  memzero(probe, sizeof(probe));
  return jsi::Value(ok);
}

jsi::Value invoke_ecdsa_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_get_public", args, count);
  auto priv = requireArrayBufferAt(rt, "ecdsa_get_public", "priv", args, count, 1);
  bool compact = requireBoolAt(rt, "ecdsa_get_public", "compact", args, count, 2);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "ecdsa_get_public: priv must be 32 bytes");
  }
  std::vector<uint8_t> out(compact ? 33 : 65);
  int err = compact
    ? ecdsa_get_public_key33(curve, priv.data(rt), out.data())
    : ecdsa_get_public_key65(curve, priv.data(rt), out.data());
  if (err != 0) {
    throw jsi::JSError(rt, "ecdsa_get_public: invalid private key");
  }
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecdsa_read_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_read_public", args, count);
  auto pub = requireArrayBufferAt(rt, "ecdsa_read_public", "pub", args, count, 1);
  bool compact = requireBoolAt(rt, "ecdsa_read_public", "compact", args, count, 2);
  size_t publen = pub.size(rt);
  if (publen != 33 && publen != 65) {
    throw jsi::JSError(rt, "ecdsa_read_public: pub must be 33 or 65 bytes");
  }
  curve_point point = {};
  if (ecdsa_read_pubkey(curve, pub.data(rt), &point) == 0) {
    memzero(&point, sizeof(point));
    throw jsi::JSError(rt, "ecdsa_read_public: invalid public key");
  }
  std::vector<uint8_t> out(compact ? 33 : 65);
  if (compact) {
    out[0] = 0x02 | (point.y.val[0] & 0x01);
    bn_write_be(&point.x, out.data() + 1);
  } else {
    out[0] = 0x04;
    bn_write_be(&point.x, out.data() + 1);
    bn_write_be(&point.y, out.data() + 33);
  }
  memzero(&point, sizeof(point));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecdsa_validate_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_validate_public", args, count);
  auto pub = requireArrayBufferAt(rt, "ecdsa_validate_public", "pub", args, count, 1);
  size_t len = pub.size(rt);
  if (len != 33 && len != 65) return jsi::Value(false);
  curve_point point = {};
  bool ok = ecdsa_read_pubkey(curve, pub.data(rt), &point) == 1;
  memzero(&point, sizeof(point));
  return jsi::Value(ok);
}

jsi::Value invoke_ecdsa_sign(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_sign", args, count);
  auto priv = requireArrayBufferAt(rt, "ecdsa_sign", "priv", args, count, 1);
  auto digest = requireArrayBufferAt(rt, "ecdsa_sign", "digest", args, count, 2);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "ecdsa_sign: priv must be 32 bytes");
  }
  if (digest.size(rt) != 32) {
    throw jsi::JSError(rt, "ecdsa_sign: digest must be 32 bytes");
  }
  // Layout: out[0] = recid, out[1..65] = sig (r||s). Single ArrayBuffer
  // keeps the JSI hop small and lets the JS wrapper slice it.
  std::vector<uint8_t> out(65);
  uint8_t pby = 0;
  int err = ecdsa_sign_digest(
    curve, priv.data(rt), digest.data(rt), out.data() + 1, &pby, nullptr);
  if (err != 0) {
    throw jsi::JSError(rt, "ecdsa_sign: signing failed");
  }
  out[0] = pby;
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecdsa_verify(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_verify", args, count);
  auto pub = requireArrayBufferAt(rt, "ecdsa_verify", "pub", args, count, 1);
  auto sig = requireArrayBufferAt(rt, "ecdsa_verify", "sig", args, count, 2);
  auto digest = requireArrayBufferAt(rt, "ecdsa_verify", "digest", args, count, 3);
  if (sig.size(rt) != 64) return jsi::Value(false);
  if (digest.size(rt) != 32) return jsi::Value(false);
  size_t publen = pub.size(rt);
  if (publen != 33 && publen != 65) return jsi::Value(false);
  bool ok =
    ecdsa_verify_digest(curve, pub.data(rt), sig.data(rt), digest.data(rt)) == 0;
  return jsi::Value(ok);
}

jsi::Value invoke_ecdsa_recover(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_recover", args, count);
  auto sig = requireArrayBufferAt(rt, "ecdsa_recover", "sig", args, count, 1);
  auto digest = requireArrayBufferAt(rt, "ecdsa_recover", "digest", args, count, 2);
  int recid = static_cast<int>(
    requireIntAt(rt, "ecdsa_recover", "recid", args, count, 3, 0, 3));
  if (sig.size(rt) != 64) {
    throw jsi::JSError(rt, "ecdsa_recover: sig must be 64 bytes");
  }
  if (digest.size(rt) != 32) {
    throw jsi::JSError(rt, "ecdsa_recover: digest must be 32 bytes");
  }
  std::vector<uint8_t> out(65);
  int err = ecdsa_recover_pub_from_sig(
    curve, out.data(), sig.data(rt), digest.data(rt), recid);
  if (err != 0) {
    throw jsi::JSError(rt, "ecdsa_recover: recovery failed");
  }
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecdsa_ecdh(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto curve = resolveCurve(rt, "ecdsa_ecdh", args, count);
  auto priv = requireArrayBufferAt(rt, "ecdsa_ecdh", "priv", args, count, 1);
  auto pub = requireArrayBufferAt(rt, "ecdsa_ecdh", "pub", args, count, 2);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "ecdsa_ecdh: priv must be 32 bytes");
  }
  size_t publen = pub.size(rt);
  if (publen != 33 && publen != 65) {
    throw jsi::JSError(rt, "ecdsa_ecdh: pub must be 33 or 65 bytes");
  }
  // ecdh_multiply writes the uncompressed 65-byte shared point; we
  // compress it ourselves before crossing the JSI boundary.
  uint8_t full[65];
  int err = ecdh_multiply(curve, priv.data(rt), pub.data(rt), full);
  if (err != 0) {
    memzero(full, sizeof(full));
    throw jsi::JSError(rt, "ecdsa_ecdh: shared secret computation failed");
  }
  std::vector<uint8_t> out(33);
  out[0] = 0x02 | (full[64] & 0x01);
  std::memcpy(out.data() + 1, full + 1, 32);
  memzero(full, sizeof(full));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecdsa_sig_to_der(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto sig = requireArrayBufferAt(rt, "ecdsa_sig_to_der", "sig", args, count, 0);
  if (sig.size(rt) != 64) {
    throw jsi::JSError(rt, "ecdsa_sig_to_der: sig must be 64 bytes");
  }
  uint8_t der[MAX_DER_SIGNATURE_SIZE];
  int der_len = ecdsa_sig_to_der(sig.data(rt), der);
  if (der_len <= 0) {
    throw jsi::JSError(rt, "ecdsa_sig_to_der: encoding failed");
  }
  std::vector<uint8_t> out(der, der + der_len);
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecdsa_sig_from_der(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto der = requireArrayBufferAt(rt, "ecdsa_sig_from_der", "der", args, count, 0);
  std::vector<uint8_t> out(64);
  if (ecdsa_sig_from_der(der.data(rt), der.size(rt), out.data()) != 0) {
    throw jsi::JSError(rt, "ecdsa_sig_from_der: invalid DER signature");
  }
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerEcdsaMethods(MethodMap& map) {
  map.push_back({"ecdsa_random_private",  1, invoke_ecdsa_random_private});
  map.push_back({"ecdsa_validate_private", 2, invoke_ecdsa_validate_private});
  map.push_back({"ecdsa_get_public",      3, invoke_ecdsa_get_public});
  map.push_back({"ecdsa_read_public",     3, invoke_ecdsa_read_public});
  map.push_back({"ecdsa_validate_public", 2, invoke_ecdsa_validate_public});
  map.push_back({"ecdsa_sign",            3, invoke_ecdsa_sign});
  map.push_back({"ecdsa_verify",          4, invoke_ecdsa_verify});
  map.push_back({"ecdsa_recover",         4, invoke_ecdsa_recover});
  map.push_back({"ecdsa_ecdh",            3, invoke_ecdsa_ecdh});
  map.push_back({"ecdsa_sig_to_der",      1, invoke_ecdsa_sig_to_der});
  map.push_back({"ecdsa_sig_from_der",    1, invoke_ecdsa_sig_from_der});
}

}

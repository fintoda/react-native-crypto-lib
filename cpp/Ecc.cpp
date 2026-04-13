// Low-level point / scalar primitives on secp256k1, shaped to cover the
// subset of tiny-secp256k1 that isn't already exposed via ecdsa/schnorr:
// pointAdd, pointAddScalar, pointMultiply, privateAdd/Sub/Negate, and
// xOnlyPointAddTweak (bare scalar tweak — not the BIP-341 tagged one,
// which already lives in schnorr_tweak_public).
//
// Errors:
//   - malformed inputs (wrong length, scalar >= n, non-point bytes) throw
//   - valid inputs that happen to produce infinity / zero return a
//     zero-length ArrayBuffer; the JS layer translates that to `null`
//     to match tiny-secp256k1's nullable return shape.

#include "Common.h"

#include <cstring>

extern "C" {
#include "bignum.h"
#include "ecdsa.h"
#include "memzero.h"
#include "secp256k1.h"
}

namespace facebook::react::cryptolib {
namespace {

jsi::Value emptyBuffer(jsi::Runtime& rt) {
  return wrapDigest(rt, std::vector<uint8_t>{});
}

void writePoint(const curve_point& p, bool compressed, uint8_t* out) {
  if (compressed) {
    out[0] = 0x02 | (p.y.val[0] & 0x01);
    bn_write_be(&p.x, out + 1);
  } else {
    out[0] = 0x04;
    bn_write_be(&p.x, out + 1);
    bn_write_be(&p.y, out + 33);
  }
}

// Reads a 32-byte BE scalar; returns false if >= n.
bool readScalarMod(const uint8_t bytes[32], bignum256* out) {
  bn_read_be(bytes, out);
  return bn_is_less(out, &secp256k1.order) != 0;
}

bool readScalarNonzero(const uint8_t bytes[32], bignum256* out) {
  bn_read_be(bytes, out);
  if (bn_is_zero(out)) return false;
  return bn_is_less(out, &secp256k1.order) != 0;
}

// --- point arithmetic ------------------------------------------------------

jsi::Value invoke_ecc_point_add(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto a = requireArrayBufferAt(rt, "ecc_point_add", "a", args, count, 0);
  auto b = requireArrayBufferAt(rt, "ecc_point_add", "b", args, count, 1);
  bool compressed = requireBoolAt(rt, "ecc_point_add", "compressed", args, count, 2);
  size_t alen = a.size(rt), blen = b.size(rt);
  if ((alen != 33 && alen != 65) || (blen != 33 && blen != 65)) {
    throw jsi::JSError(rt, "ecc_point_add: points must be 33 or 65 bytes");
  }
  curve_point A = {}, B = {};
  if (ecdsa_read_pubkey(&secp256k1, a.data(rt), &A) == 0 ||
      ecdsa_read_pubkey(&secp256k1, b.data(rt), &B) == 0) {
    throw jsi::JSError(rt, "ecc_point_add: invalid point");
  }
  // point_add(a, b) is in-place: b := a + b.
  point_add(&secp256k1, &A, &B);
  if (point_is_infinity(&B)) {
    memzero(&A, sizeof(A));
    memzero(&B, sizeof(B));
    return emptyBuffer(rt);
  }
  std::vector<uint8_t> out(compressed ? 33 : 65);
  writePoint(B, compressed, out.data());
  memzero(&A, sizeof(A));
  memzero(&B, sizeof(B));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecc_point_add_scalar(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pub = requireArrayBufferAt(rt, "ecc_point_add_scalar", "p", args, count, 0);
  auto tweak = requireArrayBufferAt(rt, "ecc_point_add_scalar", "tweak", args, count, 1);
  bool compressed = requireBoolAt(rt, "ecc_point_add_scalar", "compressed", args, count, 2);
  size_t publen = pub.size(rt);
  if (publen != 33 && publen != 65) {
    throw jsi::JSError(rt, "ecc_point_add_scalar: p must be 33 or 65 bytes");
  }
  if (tweak.size(rt) != 32) {
    throw jsi::JSError(rt, "ecc_point_add_scalar: tweak must be 32 bytes");
  }
  curve_point P = {};
  if (ecdsa_read_pubkey(&secp256k1, pub.data(rt), &P) == 0) {
    throw jsi::JSError(rt, "ecc_point_add_scalar: invalid point");
  }
  bignum256 t;
  if (!readScalarMod(tweak.data(rt), &t)) {
    memzero(&P, sizeof(P));
    throw jsi::JSError(rt, "ecc_point_add_scalar: tweak out of range");
  }
  // T = t*G; tiny-secp256k1 allows a zero tweak (result is just P).
  curve_point T = {};
  if (bn_is_zero(&t)) {
    // Q = P + 0 = P
    std::vector<uint8_t> out(compressed ? 33 : 65);
    writePoint(P, compressed, out.data());
    memzero(&P, sizeof(P));
    memzero(&t, sizeof(t));
    return wrapDigest(rt, std::move(out));
  }
  scalar_multiply(&secp256k1, &t, &T);
  point_add(&secp256k1, &T, &P);
  if (point_is_infinity(&P)) {
    memzero(&P, sizeof(P));
    memzero(&T, sizeof(T));
    memzero(&t, sizeof(t));
    return emptyBuffer(rt);
  }
  std::vector<uint8_t> out(compressed ? 33 : 65);
  writePoint(P, compressed, out.data());
  memzero(&P, sizeof(P));
  memzero(&T, sizeof(T));
  memzero(&t, sizeof(t));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecc_point_multiply(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pub = requireArrayBufferAt(rt, "ecc_point_multiply", "p", args, count, 0);
  auto tweak = requireArrayBufferAt(rt, "ecc_point_multiply", "tweak", args, count, 1);
  bool compressed = requireBoolAt(rt, "ecc_point_multiply", "compressed", args, count, 2);
  size_t publen = pub.size(rt);
  if (publen != 33 && publen != 65) {
    throw jsi::JSError(rt, "ecc_point_multiply: p must be 33 or 65 bytes");
  }
  if (tweak.size(rt) != 32) {
    throw jsi::JSError(rt, "ecc_point_multiply: tweak must be 32 bytes");
  }
  curve_point P = {};
  if (ecdsa_read_pubkey(&secp256k1, pub.data(rt), &P) == 0) {
    throw jsi::JSError(rt, "ecc_point_multiply: invalid point");
  }
  bignum256 t;
  if (!readScalarNonzero(tweak.data(rt), &t)) {
    memzero(&P, sizeof(P));
    // Matches tiny-secp256k1: zero or >= n → null.
    return emptyBuffer(rt);
  }
  curve_point Q = {};
  if (point_multiply(&secp256k1, &t, &P, &Q) != 0 || point_is_infinity(&Q)) {
    memzero(&P, sizeof(P));
    memzero(&Q, sizeof(Q));
    memzero(&t, sizeof(t));
    return emptyBuffer(rt);
  }
  std::vector<uint8_t> out(compressed ? 33 : 65);
  writePoint(Q, compressed, out.data());
  memzero(&P, sizeof(P));
  memzero(&Q, sizeof(Q));
  memzero(&t, sizeof(t));
  return wrapDigest(rt, std::move(out));
}

// --- private-key scalar ops ------------------------------------------------

jsi::Value invoke_ecc_private_add(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBufferAt(rt, "ecc_private_add", "d", args, count, 0);
  auto tweak = requireArrayBufferAt(rt, "ecc_private_add", "tweak", args, count, 1);
  if (priv.size(rt) != 32 || tweak.size(rt) != 32) {
    throw jsi::JSError(rt, "ecc_private_add: d and tweak must be 32 bytes");
  }
  bignum256 d;
  if (!readScalarNonzero(priv.data(rt), &d)) {
    throw jsi::JSError(rt, "ecc_private_add: invalid private key");
  }
  bignum256 t;
  if (!readScalarMod(tweak.data(rt), &t)) {
    memzero(&d, sizeof(d));
    throw jsi::JSError(rt, "ecc_private_add: tweak out of range");
  }
  bn_addmod(&d, &t, &secp256k1.order);
  // Unlike point add, addmod doesn't reduce — do a final mod.
  bn_mod(&d, &secp256k1.order);
  if (bn_is_zero(&d)) {
    memzero(&d, sizeof(d));
    memzero(&t, sizeof(t));
    return emptyBuffer(rt);
  }
  std::vector<uint8_t> out(32);
  bn_write_be(&d, out.data());
  memzero(&d, sizeof(d));
  memzero(&t, sizeof(t));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecc_private_sub(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBufferAt(rt, "ecc_private_sub", "d", args, count, 0);
  auto tweak = requireArrayBufferAt(rt, "ecc_private_sub", "tweak", args, count, 1);
  if (priv.size(rt) != 32 || tweak.size(rt) != 32) {
    throw jsi::JSError(rt, "ecc_private_sub: d and tweak must be 32 bytes");
  }
  bignum256 d;
  if (!readScalarNonzero(priv.data(rt), &d)) {
    throw jsi::JSError(rt, "ecc_private_sub: invalid private key");
  }
  bignum256 t;
  if (!readScalarMod(tweak.data(rt), &t)) {
    memzero(&d, sizeof(d));
    throw jsi::JSError(rt, "ecc_private_sub: tweak out of range");
  }
  // d = d - t mod n  ==  d + (n - t) mod n
  bignum256 neg_t;
  if (bn_is_zero(&t)) {
    bn_copy(&t, &neg_t);
  } else {
    bn_subtract(&secp256k1.order, &t, &neg_t);
  }
  bn_addmod(&d, &neg_t, &secp256k1.order);
  bn_mod(&d, &secp256k1.order);
  if (bn_is_zero(&d)) {
    memzero(&d, sizeof(d));
    memzero(&t, sizeof(t));
    memzero(&neg_t, sizeof(neg_t));
    return emptyBuffer(rt);
  }
  std::vector<uint8_t> out(32);
  bn_write_be(&d, out.data());
  memzero(&d, sizeof(d));
  memzero(&t, sizeof(t));
  memzero(&neg_t, sizeof(neg_t));
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_ecc_private_negate(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBuffer(rt, "ecc_private_negate", args, count);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "ecc_private_negate: d must be 32 bytes");
  }
  bignum256 d;
  if (!readScalarNonzero(priv.data(rt), &d)) {
    throw jsi::JSError(rt, "ecc_private_negate: invalid private key");
  }
  bignum256 neg;
  bn_subtract(&secp256k1.order, &d, &neg);
  std::vector<uint8_t> out(32);
  bn_write_be(&neg, out.data());
  memzero(&d, sizeof(d));
  memzero(&neg, sizeof(neg));
  return wrapDigest(rt, std::move(out));
}

// --- x-only point + bare scalar tweak (tiny-secp256k1 xOnlyPointAddTweak) --

// lift_x with even-y (BIP-340 convention).
bool liftXEven(const uint8_t x32[32], curve_point* out) {
  bn_read_be(x32, &out->x);
  if (!bn_is_less(&out->x, &secp256k1.prime)) return false;
  uncompress_coords(&secp256k1, 0, &out->x, &out->y);
  return ecdsa_validate_pubkey(&secp256k1, out) == 1;
}

jsi::Value invoke_ecc_xonly_point_add_tweak(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pub = requireArrayBufferAt(rt, "ecc_xonly_point_add_tweak", "p", args, count, 0);
  auto tweak = requireArrayBufferAt(rt, "ecc_xonly_point_add_tweak", "tweak", args, count, 1);
  if (pub.size(rt) != 32) {
    throw jsi::JSError(rt, "ecc_xonly_point_add_tweak: p must be 32 bytes");
  }
  if (tweak.size(rt) != 32) {
    throw jsi::JSError(rt, "ecc_xonly_point_add_tweak: tweak must be 32 bytes");
  }
  curve_point P = {};
  if (!liftXEven(pub.data(rt), &P)) {
    throw jsi::JSError(rt, "ecc_xonly_point_add_tweak: invalid x-only point");
  }
  bignum256 t;
  if (!readScalarMod(tweak.data(rt), &t)) {
    memzero(&P, sizeof(P));
    throw jsi::JSError(rt, "ecc_xonly_point_add_tweak: tweak out of range");
  }
  // Output: [x(32), parity(1)]; empty on infinity.
  if (bn_is_zero(&t)) {
    // Q = P + 0 — always even y because we lifted even.
    std::vector<uint8_t> out(33);
    bn_write_be(&P.x, out.data());
    out[32] = 0;
    memzero(&P, sizeof(P));
    memzero(&t, sizeof(t));
    return wrapDigest(rt, std::move(out));
  }
  curve_point T = {};
  scalar_multiply(&secp256k1, &t, &T);
  point_add(&secp256k1, &T, &P);
  if (point_is_infinity(&P)) {
    memzero(&P, sizeof(P));
    memzero(&T, sizeof(T));
    memzero(&t, sizeof(t));
    return emptyBuffer(rt);
  }
  std::vector<uint8_t> out(33);
  bn_write_be(&P.x, out.data());
  out[32] = bn_is_odd(&P.y) ? 1 : 0;
  memzero(&P, sizeof(P));
  memzero(&T, sizeof(T));
  memzero(&t, sizeof(t));
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerEccMethods(MethodMap& map) {
  map.push_back({"ecc_point_add",             3, invoke_ecc_point_add});
  map.push_back({"ecc_point_add_scalar",      3, invoke_ecc_point_add_scalar});
  map.push_back({"ecc_point_multiply",        3, invoke_ecc_point_multiply});
  map.push_back({"ecc_private_add",           2, invoke_ecc_private_add});
  map.push_back({"ecc_private_sub",           2, invoke_ecc_private_sub});
  map.push_back({"ecc_private_negate",        1, invoke_ecc_private_negate});
  map.push_back({"ecc_xonly_point_add_tweak", 2, invoke_ecc_xonly_point_add_tweak});
}

}

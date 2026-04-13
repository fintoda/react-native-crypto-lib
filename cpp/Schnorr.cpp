// Schnorr / BIP-340 ----------------------------------------------------------
// trezor-crypto ships BIP-340 only via zkp_bip340.c, which pulls in the
// full libsecp256k1-zkp submodule. We don't want that dependency, so we
// implement BIP-340 directly on top of the bignum / point primitives we
// already have. All operations below are secp256k1-only.

#include "Common.h"

#include <cstring>
#include <mutex>

extern "C" {
#include "bignum.h"
#include "ecdsa.h"
#include "memzero.h"
#include "secp256k1.h"
#include "sha2.h"
}

namespace facebook::react::cryptolib {
namespace {

// Precomputed SHA-256 of the BIP-340 / BIP-341 tags. Used via the
// tagged_hash helper: SHA256(SHA256(tag) || SHA256(tag) || m).
// Computed once at module startup to avoid hashing the tag on every call.
struct TaggedHashPrefix {
  uint8_t bytes[32];
};
TaggedHashPrefix kTagAux;
TaggedHashPrefix kTagNonce;
TaggedHashPrefix kTagChallenge;
TaggedHashPrefix kTagTapTweak;
std::once_flag kTagsOnce;

void initTaggedHashPrefixes() {
  std::call_once(kTagsOnce, [] {
    auto tag = [](const char* s, TaggedHashPrefix& out) {
      sha256_Raw(reinterpret_cast<const uint8_t*>(s), std::strlen(s), out.bytes);
    };
    tag("BIP0340/aux",       kTagAux);
    tag("BIP0340/nonce",     kTagNonce);
    tag("BIP0340/challenge", kTagChallenge);
    tag("TapTweak",          kTagTapTweak);
  });
}

// tagged_hash(tag, m0 || m1) → 32 bytes.
void taggedHash2(
  const TaggedHashPrefix& tagHash,
  const uint8_t* m0, size_t m0Len,
  const uint8_t* m1, size_t m1Len,
  uint8_t out[32]
) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, tagHash.bytes, 32);
  sha256_Update(&ctx, tagHash.bytes, 32);
  if (m0Len) sha256_Update(&ctx, m0, m0Len);
  if (m1Len) sha256_Update(&ctx, m1, m1Len);
  sha256_Final(&ctx, out);
}

void taggedHash3(
  const TaggedHashPrefix& tagHash,
  const uint8_t* m0, size_t m0Len,
  const uint8_t* m1, size_t m1Len,
  const uint8_t* m2, size_t m2Len,
  uint8_t out[32]
) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, tagHash.bytes, 32);
  sha256_Update(&ctx, tagHash.bytes, 32);
  if (m0Len) sha256_Update(&ctx, m0, m0Len);
  if (m1Len) sha256_Update(&ctx, m1, m1Len);
  if (m2Len) sha256_Update(&ctx, m2, m2Len);
  sha256_Final(&ctx, out);
}

// lift_x per BIP-340: given 32-byte x, return the point (x, y) on secp256k1
// with even y, or fail if x is out of range or not on the curve.
bool schnorrLiftX(const uint8_t x32[32], curve_point* out) {
  bn_read_be(x32, &out->x);
  if (!bn_is_less(&out->x, &secp256k1.prime)) return false;
  // odd = 0 requests the even-y root.
  uncompress_coords(&secp256k1, 0, &out->x, &out->y);
  // uncompress_coords runs bn_sqrt unconditionally, so we must verify the
  // resulting point is actually on the curve (i.e. x^3+7 was a QR).
  return ecdsa_validate_pubkey(&secp256k1, out) == 1;
}

// Reads a 32-byte BE scalar into `out`, returning false if it is >= order.
bool schnorrReadScalar(const uint8_t bytes32[32], bignum256* out) {
  bn_read_be(bytes32, out);
  return bn_is_less(out, &secp256k1.order) != 0;
}

bool schnorrGetPublicX(const uint8_t priv[32], uint8_t out_x[32]) {
  initTaggedHashPrefixes();
  bignum256 d;
  bn_read_be(priv, &d);
  if (bn_is_zero(&d) || !bn_is_less(&d, &secp256k1.order)) {
    memzero(&d, sizeof(d));
    return false;
  }
  curve_point P;
  scalar_multiply(&secp256k1, &d, &P);
  bn_write_be(&P.x, out_x);
  memzero(&d, sizeof(d));
  memzero(&P, sizeof(P));
  return true;
}

bool schnorrVerifyPublicX(const uint8_t x32[32]) {
  curve_point P;
  bool ok = schnorrLiftX(x32, &P);
  memzero(&P, sizeof(P));
  return ok;
}

// BIP-340 sign. aux32 may be null → treated as 32 zero bytes.
bool schnorrSign(
  const uint8_t priv[32],
  const uint8_t msg32[32],
  const uint8_t* aux32,
  uint8_t sig[64]
) {
  initTaggedHashPrefixes();

  // --- step 1..3: d = d' (if P.y even) else n - d'. -----------------------
  bignum256 d;
  bn_read_be(priv, &d);
  if (bn_is_zero(&d) || !bn_is_less(&d, &secp256k1.order)) {
    memzero(&d, sizeof(d));
    return false;
  }
  curve_point P;
  scalar_multiply(&secp256k1, &d, &P);
  if (bn_is_odd(&P.y)) {
    bn_subtract(&secp256k1.order, &d, &d);
  }
  uint8_t d_bytes[32];
  uint8_t p_bytes[32];
  bn_write_be(&d, d_bytes);
  bn_write_be(&P.x, p_bytes);

  // --- step 4..5: t = d XOR H_aux(aux); rand = H_nonce(t || P || m). ------
  uint8_t h_aux[32];
  if (aux32) {
    taggedHash2(kTagAux, aux32, 32, nullptr, 0, h_aux);
  } else {
    uint8_t zeros[32] = {};
    taggedHash2(kTagAux, zeros, 32, nullptr, 0, h_aux);
  }
  uint8_t t_bytes[32];
  for (int i = 0; i < 32; i++) t_bytes[i] = d_bytes[i] ^ h_aux[i];

  uint8_t rand32[32];
  taggedHash3(kTagNonce, t_bytes, 32, p_bytes, 32, msg32, 32, rand32);

  // --- step 6: k' = int(rand) mod n, fail if zero. ------------------------
  bignum256 k;
  bn_read_be(rand32, &k);
  bn_mod(&k, &secp256k1.order);
  if (bn_is_zero(&k)) {
    memzero(&d, sizeof(d));
    memzero(&P, sizeof(P));
    memzero(d_bytes, sizeof(d_bytes));
    memzero(p_bytes, sizeof(p_bytes));
    memzero(h_aux, sizeof(h_aux));
    memzero(t_bytes, sizeof(t_bytes));
    memzero(rand32, sizeof(rand32));
    memzero(&k, sizeof(k));
    return false;
  }

  // --- step 7..8: R = k'*G; k = k' if R.y even else n-k'. -----------------
  curve_point R;
  scalar_multiply(&secp256k1, &k, &R);
  if (bn_is_odd(&R.y)) {
    bn_subtract(&secp256k1.order, &k, &k);
  }

  // --- step 9..10: e = H_challenge(R.x || P.x || m) mod n. ----------------
  uint8_t r_bytes[32];
  bn_write_be(&R.x, r_bytes);

  uint8_t e_bytes[32];
  taggedHash3(kTagChallenge, r_bytes, 32, p_bytes, 32, msg32, 32, e_bytes);

  bignum256 e;
  bn_read_be(e_bytes, &e);
  bn_mod(&e, &secp256k1.order);

  // --- step 11: s = (k + e*d) mod n. --------------------------------------
  // bn_multiply(a, b, p) → b = a*b mod p. Work on `d` so we don't need an
  // extra register, then add k.
  bn_multiply(&e, &d, &secp256k1.order);  // d := e*d (mod n)
  bn_addmod(&d, &k, &secp256k1.order);    // d := e*d + k (mod n)

  // sig = R.x || s
  std::memcpy(sig, r_bytes, 32);
  bn_write_be(&d, sig + 32);

  memzero(&d, sizeof(d));
  memzero(&k, sizeof(k));
  memzero(&e, sizeof(e));
  memzero(&P, sizeof(P));
  memzero(&R, sizeof(R));
  memzero(d_bytes, sizeof(d_bytes));
  memzero(p_bytes, sizeof(p_bytes));
  memzero(t_bytes, sizeof(t_bytes));
  memzero(h_aux, sizeof(h_aux));
  memzero(r_bytes, sizeof(r_bytes));
  memzero(e_bytes, sizeof(e_bytes));
  memzero(rand32, sizeof(rand32));
  return true;
}

bool schnorrVerify(
  const uint8_t pub_x[32],
  const uint8_t sig[64],
  const uint8_t msg32[32]
) {
  initTaggedHashPrefixes();

  curve_point P;
  if (!schnorrLiftX(pub_x, &P)) return false;

  // r < p
  bignum256 r;
  bn_read_be(sig, &r);
  if (!bn_is_less(&r, &secp256k1.prime)) return false;

  // s < n
  bignum256 s;
  if (!schnorrReadScalar(sig + 32, &s)) return false;

  // e = H_challenge(r || P.x || m) mod n.
  uint8_t p_bytes[32];
  bn_write_be(&P.x, p_bytes);
  uint8_t e_bytes[32];
  taggedHash3(kTagChallenge, sig, 32, p_bytes, 32, msg32, 32, e_bytes);
  bignum256 e;
  bn_read_be(e_bytes, &e);
  bn_mod(&e, &secp256k1.order);

  // R = s*G - e*P. Negate e (mod n), then R = s*G + (n-e)*P via
  // scalar_multiply + point_multiply + point_add.
  curve_point sG;
  scalar_multiply(&secp256k1, &s, &sG);

  // eP_neg = (n - e) * P
  bignum256 neg_e;
  bn_subtract(&secp256k1.order, &e, &neg_e);
  curve_point eP_neg;
  if (point_multiply(&secp256k1, &neg_e, &P, &eP_neg) != 0) return false;

  // R = sG + eP_neg
  curve_point R = sG;
  point_add(&secp256k1, &eP_neg, &R);
  if (point_is_infinity(&R)) return false;
  if (bn_is_odd(&R.y)) return false;
  return bn_is_equal(&R.x, &r) != 0;
}

// BIP-341 TapTweak on a public x-only key. merkleRoot may be null/empty.
bool schnorrTweakPublic(
  const uint8_t pub_x[32],
  const uint8_t* merkleRoot, size_t merkleRootLen,
  uint8_t out_x[32],
  int* parity
) {
  initTaggedHashPrefixes();

  curve_point P;
  if (!schnorrLiftX(pub_x, &P)) return false;

  uint8_t t_hash[32];
  taggedHash2(kTagTapTweak, pub_x, 32, merkleRoot, merkleRootLen, t_hash);

  bignum256 t;
  bn_read_be(t_hash, &t);
  if (!bn_is_less(&t, &secp256k1.order)) return false;

  curve_point T;
  scalar_multiply(&secp256k1, &t, &T);

  // Q = P + T
  curve_point Q = P;
  point_add(&secp256k1, &T, &Q);
  if (point_is_infinity(&Q)) return false;

  bn_write_be(&Q.x, out_x);
  if (parity) *parity = bn_is_odd(&Q.y) ? 1 : 0;

  memzero(&P, sizeof(P));
  memzero(&T, sizeof(T));
  memzero(&Q, sizeof(Q));
  memzero(&t, sizeof(t));
  return true;
}

bool schnorrTweakPrivate(
  const uint8_t priv[32],
  const uint8_t* merkleRoot, size_t merkleRootLen,
  uint8_t out_priv[32]
) {
  initTaggedHashPrefixes();

  bignum256 d;
  bn_read_be(priv, &d);
  if (bn_is_zero(&d) || !bn_is_less(&d, &secp256k1.order)) return false;

  curve_point P;
  scalar_multiply(&secp256k1, &d, &P);
  if (bn_is_odd(&P.y)) {
    bn_subtract(&secp256k1.order, &d, &d);
  }

  uint8_t p_bytes[32];
  bn_write_be(&P.x, p_bytes);
  uint8_t t_hash[32];
  taggedHash2(kTagTapTweak, p_bytes, 32, merkleRoot, merkleRootLen, t_hash);

  bignum256 t;
  bn_read_be(t_hash, &t);
  if (!bn_is_less(&t, &secp256k1.order)) return false;

  bn_addmod(&d, &t, &secp256k1.order);
  if (bn_is_zero(&d)) return false;
  bn_write_be(&d, out_priv);

  memzero(&d, sizeof(d));
  memzero(&t, sizeof(t));
  memzero(&P, sizeof(P));
  return true;
}

// --- JSI bindings ----------------------------------------------------------

jsi::Value invoke_schnorr_get_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto priv = requireArrayBuffer(rt, "schnorr_get_public", args, count);
  if (priv.size(rt) != 32) {
    throw jsi::JSError(rt, "schnorr_get_public: priv must be 32 bytes");
  }
  std::vector<uint8_t> out(32);
  if (!schnorrGetPublicX(priv.data(rt), out.data())) {
    throw jsi::JSError(rt, "schnorr_get_public: invalid private key");
  }
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_schnorr_verify_public(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pub = requireArrayBuffer(rt, "schnorr_verify_public", args, count);
  if (pub.size(rt) != 32) return jsi::Value(false);
  return jsi::Value(schnorrVerifyPublicX(pub.data(rt)));
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
  if (!schnorrSign(priv.data(rt), digest.data(rt), auxPtr, out.data())) {
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
    schnorrVerify(pub.data(rt), sig.data(rt), digest.data(rt)));
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
  if (!schnorrTweakPublic(pub.data(rt), rootPtr, rootLen, out.data(), &parity)) {
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
  if (!schnorrTweakPrivate(priv.data(rt), rootPtr, rootLen, out.data())) {
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

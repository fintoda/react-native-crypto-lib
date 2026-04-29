#pragma once

// BIP-340 / BIP-341 helpers shared between cpp/Schnorr.cpp (the JSI
// thunks) and cpp/SecureKVSign.cpp (which signs with derived keys
// without ever returning the private scalar to JS).
//
// Functions and shared state live as `inline` definitions in this
// header so both translation units pick up the same single instance
// of the tagged-hash prefix table (computed once at first use via
// std::call_once).

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>

extern "C" {
#include "bignum.h"
#include "ecdsa.h"
#include "memzero.h"
#include "secp256k1.h"
#include "sha2.h"
}

namespace facebook::react::cryptolib::schnorr_internal {

struct TaggedHashPrefix {
  uint8_t bytes[32];
};

inline TaggedHashPrefix kTagAux{};
inline TaggedHashPrefix kTagNonce{};
inline TaggedHashPrefix kTagChallenge{};
inline TaggedHashPrefix kTagTapTweak{};
inline std::once_flag kTagsOnce;

inline void initTaggedHashPrefixes() {
  std::call_once(kTagsOnce, [] {
    auto tag = [](const char* s, TaggedHashPrefix& out) {
      sha256_Raw(
        reinterpret_cast<const uint8_t*>(s), std::strlen(s), out.bytes);
    };
    tag("BIP0340/aux",       kTagAux);
    tag("BIP0340/nonce",     kTagNonce);
    tag("BIP0340/challenge", kTagChallenge);
    tag("TapTweak",          kTagTapTweak);
  });
}

inline void taggedHash2(
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

inline void taggedHash3(
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

// lift_x per BIP-340: given 32-byte x, return the point (x, y) on
// secp256k1 with even y, or fail if x is out of range or not on the curve.
inline bool liftX(const uint8_t x32[32], curve_point* out) {
  bn_read_be(x32, &out->x);
  if (!bn_is_less(&out->x, &secp256k1.prime)) return false;
  uncompress_coords(&secp256k1, 0, &out->x, &out->y);
  return ecdsa_validate_pubkey(&secp256k1, out) == 1;
}

inline bool readScalar(const uint8_t bytes32[32], bignum256* out) {
  bn_read_be(bytes32, out);
  return bn_is_less(out, &secp256k1.order) != 0;
}

inline bool getPublicX(const uint8_t priv[32], uint8_t out_x[32]) {
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

inline bool verifyPublicX(const uint8_t x32[32]) {
  curve_point P;
  bool ok = liftX(x32, &P);
  memzero(&P, sizeof(P));
  return ok;
}

// BIP-340 sign. aux32 may be null → treated as 32 zero bytes.
inline bool sign(
  const uint8_t priv[32],
  const uint8_t msg32[32],
  const uint8_t* aux32,
  uint8_t sig[64]
) {
  initTaggedHashPrefixes();

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

  curve_point R;
  scalar_multiply(&secp256k1, &k, &R);
  if (bn_is_odd(&R.y)) {
    bn_subtract(&secp256k1.order, &k, &k);
  }

  uint8_t r_bytes[32];
  bn_write_be(&R.x, r_bytes);

  uint8_t e_bytes[32];
  taggedHash3(kTagChallenge, r_bytes, 32, p_bytes, 32, msg32, 32, e_bytes);

  bignum256 e;
  bn_read_be(e_bytes, &e);
  bn_mod(&e, &secp256k1.order);

  bn_multiply(&e, &d, &secp256k1.order);
  bn_addmod(&d, &k, &secp256k1.order);

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

inline bool verify(
  const uint8_t pub_x[32],
  const uint8_t sig[64],
  const uint8_t msg32[32]
) {
  initTaggedHashPrefixes();

  curve_point P;
  if (!liftX(pub_x, &P)) return false;

  bignum256 r;
  bn_read_be(sig, &r);
  if (!bn_is_less(&r, &secp256k1.prime)) return false;

  bignum256 s;
  if (!readScalar(sig + 32, &s)) return false;

  uint8_t p_bytes[32];
  bn_write_be(&P.x, p_bytes);
  uint8_t e_bytes[32];
  taggedHash3(kTagChallenge, sig, 32, p_bytes, 32, msg32, 32, e_bytes);
  bignum256 e;
  bn_read_be(e_bytes, &e);
  bn_mod(&e, &secp256k1.order);

  curve_point sG;
  scalar_multiply(&secp256k1, &s, &sG);

  bignum256 neg_e;
  bn_subtract(&secp256k1.order, &e, &neg_e);
  curve_point eP_neg;
  if (point_multiply(&secp256k1, &neg_e, &P, &eP_neg) != 0) return false;

  curve_point R = sG;
  point_add(&secp256k1, &eP_neg, &R);
  if (point_is_infinity(&R)) return false;
  if (bn_is_odd(&R.y)) return false;
  return bn_is_equal(&R.x, &r) != 0;
}

inline bool tweakPublic(
  const uint8_t pub_x[32],
  const uint8_t* merkleRoot, size_t merkleRootLen,
  uint8_t out_x[32],
  int* parity
) {
  initTaggedHashPrefixes();

  curve_point P;
  if (!liftX(pub_x, &P)) return false;

  uint8_t t_hash[32];
  taggedHash2(kTagTapTweak, pub_x, 32, merkleRoot, merkleRootLen, t_hash);

  bignum256 t;
  bn_read_be(t_hash, &t);
  if (!bn_is_less(&t, &secp256k1.order)) return false;

  curve_point T;
  scalar_multiply(&secp256k1, &t, &T);

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

inline bool tweakPrivate(
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

}  // namespace facebook::react::cryptolib::schnorr_internal

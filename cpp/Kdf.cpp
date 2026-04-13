#include "Common.h"

#include <algorithm>
#include <cstring>

extern "C" {
#include "hmac.h"
#include "pbkdf2.h"
#include "sha2.h"
}

namespace facebook::react::cryptolib {
namespace {

// Caps for PBKDF2 / HKDF parameters. The output length cap matches HKDF's
// hard limit (255 * HashLen for SHA-512), and we apply the same to PBKDF2
// for consistency. Iterations are capped to avoid pathological JS calls
// that would block the JS thread for minutes.
constexpr int kKdfMaxOutLen = 255 * 64;        // 16 320 bytes
constexpr uint32_t kKdfMaxIterations = 10'000'000;

jsi::Value invoke_pbkdf2_sha256(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pass = requireArrayBufferAt(rt, "kdf_pbkdf2_sha256", "password", args, count, 0);
  auto salt = requireArrayBufferAt(rt, "kdf_pbkdf2_sha256", "salt", args, count, 1);
  if (pass.size(rt) > INT_MAX) {
    throw jsi::JSError(rt, "kdf_pbkdf2_sha256: password too large");
  }
  if (salt.size(rt) > INT_MAX) {
    throw jsi::JSError(rt, "kdf_pbkdf2_sha256: salt too large");
  }
  uint32_t iters = static_cast<uint32_t>(requireIntAt(
    rt, "kdf_pbkdf2_sha256", "iterations", args, count, 2, 1, kKdfMaxIterations));
  int outlen = static_cast<int>(requireIntAt(
    rt, "kdf_pbkdf2_sha256", "length", args, count, 3, 1, kKdfMaxOutLen));
  std::vector<uint8_t> out(outlen);
  pbkdf2_hmac_sha256(pass.data(rt), static_cast<int>(pass.size(rt)),
                     salt.data(rt), static_cast<int>(salt.size(rt)),
                     iters, out.data(), outlen);
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_pbkdf2_sha512(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto pass = requireArrayBufferAt(rt, "kdf_pbkdf2_sha512", "password", args, count, 0);
  auto salt = requireArrayBufferAt(rt, "kdf_pbkdf2_sha512", "salt", args, count, 1);
  if (pass.size(rt) > INT_MAX) {
    throw jsi::JSError(rt, "kdf_pbkdf2_sha512: password too large");
  }
  if (salt.size(rt) > INT_MAX) {
    throw jsi::JSError(rt, "kdf_pbkdf2_sha512: salt too large");
  }
  uint32_t iters = static_cast<uint32_t>(requireIntAt(
    rt, "kdf_pbkdf2_sha512", "iterations", args, count, 2, 1, kKdfMaxIterations));
  int outlen = static_cast<int>(requireIntAt(
    rt, "kdf_pbkdf2_sha512", "length", args, count, 3, 1, kKdfMaxOutLen));
  std::vector<uint8_t> out(outlen);
  pbkdf2_hmac_sha512(pass.data(rt), static_cast<int>(pass.size(rt)),
                     salt.data(rt), static_cast<int>(salt.size(rt)),
                     iters, out.data(), outlen);
  return wrapDigest(rt, std::move(out));
}

// HKDF (RFC 5869) — trezor-crypto doesn't ship HKDF, so we build it on
// top of its hmac_sha{256,512} primitives.
template <
  size_t HashLen,
  void (*Hmac)(const uint8_t*, uint32_t, const uint8_t*, uint32_t, uint8_t*)
>
void hkdf(
  jsi::Runtime& rt,
  const char* methodName,
  const uint8_t* salt, size_t saltLen,
  const uint8_t* ikm,  size_t ikmLen,
  const uint8_t* info, size_t infoLen,
  uint8_t* out, size_t outLen
) {
  if (saltLen > UINT32_MAX) {
    throw jsi::JSError(rt, std::string(methodName) + ": salt too large");
  }
  if (ikmLen > UINT32_MAX) {
    throw jsi::JSError(rt, std::string(methodName) + ": ikm too large");
  }
  if (infoLen > UINT32_MAX) {
    throw jsi::JSError(rt, std::string(methodName) + ": info too large");
  }
  // Extract: PRK = HMAC(salt, IKM). RFC 5869: if salt is absent, use a
  // string of HashLen zeros as the salt.
  uint8_t zeroSalt[HashLen] = {};
  if (saltLen == 0) {
    salt = zeroSalt;
    saltLen = HashLen;
  }
  uint8_t prk[HashLen];
  Hmac(salt, static_cast<uint32_t>(saltLen),
       ikm,  static_cast<uint32_t>(ikmLen),
       prk);

  // Expand: T(i) = HMAC(PRK, T(i-1) || info || i), OKM = T(1) || T(2) || ...
  uint8_t prev[HashLen];
  size_t prevLen = 0;
  size_t produced = 0;
  uint8_t counter = 1;
  std::vector<uint8_t> buf;
  buf.reserve(HashLen + infoLen + 1);
  while (produced < outLen) {
    buf.assign(prev, prev + prevLen);
    buf.insert(buf.end(), info, info + infoLen);
    buf.push_back(counter);

    uint8_t t[HashLen];
    Hmac(prk, HashLen, buf.data(), static_cast<uint32_t>(buf.size()), t);

    size_t take = std::min(static_cast<size_t>(HashLen), outLen - produced);
    std::memcpy(out + produced, t, take);
    produced += take;
    std::memcpy(prev, t, HashLen);
    prevLen = HashLen;
    counter++;
  }
}

jsi::Value invoke_hkdf_sha256(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto ikm  = requireArrayBufferAt(rt, "kdf_hkdf_sha256", "ikm",  args, count, 0);
  auto salt = requireArrayBufferAt(rt, "kdf_hkdf_sha256", "salt", args, count, 1);
  auto info = requireArrayBufferAt(rt, "kdf_hkdf_sha256", "info", args, count, 2);
  // RFC 5869: max OKM length = 255 * HashLen
  int outlen = static_cast<int>(requireIntAt(
    rt, "kdf_hkdf_sha256", "length", args, count, 3, 1, 255 * 32));
  std::vector<uint8_t> out(outlen);
  hkdf<SHA256_DIGEST_LENGTH, hmac_sha256>(
    rt, "kdf_hkdf_sha256",
    salt.data(rt), salt.size(rt),
    ikm.data(rt),  ikm.size(rt),
    info.data(rt), info.size(rt),
    out.data(), out.size());
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_hkdf_sha512(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto ikm  = requireArrayBufferAt(rt, "kdf_hkdf_sha512", "ikm",  args, count, 0);
  auto salt = requireArrayBufferAt(rt, "kdf_hkdf_sha512", "salt", args, count, 1);
  auto info = requireArrayBufferAt(rt, "kdf_hkdf_sha512", "info", args, count, 2);
  int outlen = static_cast<int>(requireIntAt(
    rt, "kdf_hkdf_sha512", "length", args, count, 3, 1, 255 * 64));
  std::vector<uint8_t> out(outlen);
  hkdf<SHA512_DIGEST_LENGTH, hmac_sha512>(
    rt, "kdf_hkdf_sha512",
    salt.data(rt), salt.size(rt),
    ikm.data(rt),  ikm.size(rt),
    info.data(rt), info.size(rt),
    out.data(), out.size());
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerKdfMethods(MethodMap& map) {
  map.push_back({"kdf_pbkdf2_sha256", 4, invoke_pbkdf2_sha256});
  map.push_back({"kdf_pbkdf2_sha512", 4, invoke_pbkdf2_sha512});
  map.push_back({"kdf_hkdf_sha256",   4, invoke_hkdf_sha256});
  map.push_back({"kdf_hkdf_sha512",   4, invoke_hkdf_sha512});
}

}

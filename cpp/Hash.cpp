#include "Common.h"

extern "C" {
#include "blake256.h"
#include "blake2b.h"
#include "blake2s.h"
#include "groestl.h"
#include "memzero.h"
#include "ripemd160.h"
#include "sha2.h"
#include "sha3.h"
}

namespace facebook::react::cryptolib {
namespace {

// Each hash function follows the same shape: read one ArrayBuffer arg,
// allocate the right output size, run the C function, return as a new
// ArrayBuffer. The HASH_FN macro keeps the boilerplate readable.

#define HASH_FN(name, methodName, digestLen, callExpr)                   \
  jsi::Value name(                                                       \
    jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count \
  ) {                                                                    \
    auto in = requireArrayBuffer(rt, methodName, args, count);           \
    std::vector<uint8_t> out(digestLen);                                 \
    const uint8_t* inData = safeData(rt, in);                             \
    size_t inSize = in.size(rt);                                         \
    callExpr;                                                            \
    return wrapDigest(rt, std::move(out));                               \
  }

HASH_FN(invoke_sha1,       "hash_sha1",       SHA1_DIGEST_LENGTH,
        sha1_Raw(inData, inSize, out.data()))
HASH_FN(invoke_sha256,     "hash_sha256",     SHA256_DIGEST_LENGTH,
        sha256_Raw(inData, inSize, out.data()))
HASH_FN(invoke_sha384,     "hash_sha384",     SHA384_DIGEST_LENGTH,
        sha384_Raw(inData, inSize, out.data()))
HASH_FN(invoke_sha512,     "hash_sha512",     SHA512_DIGEST_LENGTH,
        sha512_Raw(inData, inSize, out.data()))
HASH_FN(invoke_sha3_256,   "hash_sha3_256",   SHA3_256_DIGEST_LENGTH,
        sha3_256(inData, inSize, out.data()))
HASH_FN(invoke_sha3_512,   "hash_sha3_512",   SHA3_512_DIGEST_LENGTH,
        sha3_512(inData, inSize, out.data()))
HASH_FN(invoke_keccak_256, "hash_keccak_256", SHA3_256_DIGEST_LENGTH,
        keccak_256(inData, inSize, out.data()))
HASH_FN(invoke_keccak_512, "hash_keccak_512", SHA3_512_DIGEST_LENGTH,
        keccak_512(inData, inSize, out.data()))
HASH_FN(invoke_ripemd160,  "hash_ripemd160",  RIPEMD160_DIGEST_LENGTH,
        ripemd160(inData, inSize, out.data()))

#undef HASH_FN

// blake256 has no one-shot Raw function — drive it via Init/Update/Final.
jsi::Value invoke_blake256(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto in = requireArrayBuffer(rt, "hash_blake256", args, count);
  std::vector<uint8_t> out(BLAKE256_DIGEST_LENGTH);
  BLAKE256_CTX ctx;
  blake256_Init(&ctx);
  blake256_Update(&ctx, safeData(rt, in), in.size(rt));
  blake256_Final(&ctx, out.data());
  return wrapDigest(rt, std::move(out));
}

// blake2b/2s have configurable output length. Default to the natural
// "full" sizes (64 / 32) — variants with custom outlen / key / personal
// can be added later as separate methods.
jsi::Value invoke_blake2b(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto in = requireArrayBuffer(rt, "hash_blake2b", args, count);
  std::vector<uint8_t> out(BLAKE2B_OUTBYTES);
  blake2b_state ctx;
  blake2b_Init(&ctx, BLAKE2B_OUTBYTES);
  blake2b_Update(&ctx, safeData(rt, in), in.size(rt));
  blake2b_Final(&ctx, out.data(), BLAKE2B_OUTBYTES);
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_blake2s(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto in = requireArrayBuffer(rt, "hash_blake2s", args, count);
  std::vector<uint8_t> out(BLAKE2S_OUTBYTES);
  blake2s_state ctx;
  blake2s_Init(&ctx, BLAKE2S_OUTBYTES);
  blake2s_Update(&ctx, safeData(rt, in), in.size(rt));
  blake2s_Final(&ctx, out.data(), BLAKE2S_OUTBYTES);
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_groestl512(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto in = requireArrayBuffer(rt, "hash_groestl512", args, count);
  std::vector<uint8_t> out(64);
  GROESTL512_CTX ctx;
  groestl512_Init(&ctx);
  groestl512_Update(&ctx, safeData(rt, in), in.size(rt));
  groestl512_Final(&ctx, out.data());
  return wrapDigest(rt, std::move(out));
}

// sha256d = sha256(sha256(x)) — Bitcoin's standard double hash.
jsi::Value invoke_sha256d(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto in = requireArrayBuffer(rt, "hash_sha256d", args, count);
  uint8_t first[SHA256_DIGEST_LENGTH];
  sha256_Raw(safeData(rt, in), in.size(rt), first);
  std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
  sha256_Raw(first, SHA256_DIGEST_LENGTH, out.data());
  memzero(first, sizeof(first));
  return wrapDigest(rt, std::move(out));
}

// hash160 = ripemd160(sha256(x)) — Bitcoin/legacy address hashing.
jsi::Value invoke_hash160(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto in = requireArrayBuffer(rt, "hash_hash160", args, count);
  uint8_t mid[SHA256_DIGEST_LENGTH];
  sha256_Raw(safeData(rt, in), in.size(rt), mid);
  std::vector<uint8_t> out(RIPEMD160_DIGEST_LENGTH);
  ripemd160(mid, SHA256_DIGEST_LENGTH, out.data());
  memzero(mid, sizeof(mid));
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerHashMethods(MethodMap& map) {
  map.push_back({"hash_sha1",       1, invoke_sha1});
  map.push_back({"hash_sha256",     1, invoke_sha256});
  map.push_back({"hash_sha384",     1, invoke_sha384});
  map.push_back({"hash_sha512",     1, invoke_sha512});
  map.push_back({"hash_sha3_256",   1, invoke_sha3_256});
  map.push_back({"hash_sha3_512",   1, invoke_sha3_512});
  map.push_back({"hash_keccak_256", 1, invoke_keccak_256});
  map.push_back({"hash_keccak_512", 1, invoke_keccak_512});
  map.push_back({"hash_ripemd160",  1, invoke_ripemd160});
  map.push_back({"hash_blake256",   1, invoke_blake256});
  map.push_back({"hash_blake2b",    1, invoke_blake2b});
  map.push_back({"hash_blake2s",    1, invoke_blake2s});
  map.push_back({"hash_groestl512", 1, invoke_groestl512});
  map.push_back({"hash_sha256d",    1, invoke_sha256d});
  map.push_back({"hash_hash160",    1, invoke_hash160});
}

}

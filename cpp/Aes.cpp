// AES-256 in CBC, CTR and GCM modes. Key size is hard-coded to 256 bits
// per the library's scope — 128/192 are intentionally not exposed.
// IV / nonce is always caller-provided. CBC padding is selected per-call
// via a string ("pkcs7" | "none").

#include "Common.h"

#include <cstring>

extern "C" {
#include "aes/aes.h"
#include "aes/aesgcm.h"
#include "memzero.h"
}

namespace facebook::react::cryptolib {
namespace {

constexpr size_t kAesBlock = 16;
constexpr size_t kAesKey = 32;
constexpr size_t kGcmTag = 16;

enum class CbcPadding { None, Pkcs7 };

CbcPadding parsePadding(jsi::Runtime& rt, const char* method, const std::string& s) {
  if (s == "pkcs7") return CbcPadding::Pkcs7;
  if (s == "none") return CbcPadding::None;
  throw jsi::JSError(
    rt,
    std::string(method) + ": padding must be \"pkcs7\" or \"none\"");
}

// --- AES-256-CBC -----------------------------------------------------------

jsi::Value invoke_aes_256_cbc_encrypt(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto key = requireArrayBufferAt(rt, "aes_256_cbc_encrypt", "key", args, count, 0);
  auto iv = requireArrayBufferAt(rt, "aes_256_cbc_encrypt", "iv", args, count, 1);
  auto data = requireArrayBufferAt(rt, "aes_256_cbc_encrypt", "data", args, count, 2);
  auto padStr = requireStringAt(rt, "aes_256_cbc_encrypt", "padding", args, count, 3);
  auto padding = parsePadding(rt, "aes_256_cbc_encrypt", padStr);

  if (key.size(rt) != kAesKey) {
    throw jsi::JSError(rt, "aes_256_cbc_encrypt: key must be 32 bytes");
  }
  if (iv.size(rt) != kAesBlock) {
    throw jsi::JSError(rt, "aes_256_cbc_encrypt: iv must be 16 bytes");
  }
  size_t inLen = data.size(rt);
  size_t outLen;
  if (padding == CbcPadding::Pkcs7) {
    // PKCS#7 always appends at least one block — if the input already
    // aligns, a full 16-byte block of 0x10 is added so that unpad can
    // unambiguously tell "no padding" from "16 bytes of 0x10".
    outLen = inLen + (kAesBlock - inLen % kAesBlock);
  } else {
    if (inLen % kAesBlock != 0) {
      throw jsi::JSError(
        rt, "aes_256_cbc_encrypt: data length must be a multiple of 16 when padding=\"none\"");
    }
    outLen = inLen;
  }

  std::vector<uint8_t> buf(outLen);
  std::memcpy(buf.data(), data.data(rt), inLen);
  if (padding == CbcPadding::Pkcs7) {
    uint8_t padByte = static_cast<uint8_t>(outLen - inLen);
    for (size_t i = inLen; i < outLen; i++) buf[i] = padByte;
  }

  aes_encrypt_ctx cx;
  if (aes_encrypt_key256(key.data(rt), &cx) != EXIT_SUCCESS) {
    memzero(&cx, sizeof(cx));
    throw jsi::JSError(rt, "aes_256_cbc_encrypt: key schedule failed");
  }
  // trezor's aes_cbc_encrypt updates iv in-place. Copy first so we
  // don't disturb the caller's buffer across the JSI boundary.
  uint8_t ivCopy[kAesBlock];
  std::memcpy(ivCopy, iv.data(rt), kAesBlock);
  int rc = aes_cbc_encrypt(buf.data(), buf.data(), static_cast<int>(outLen), ivCopy, &cx);
  memzero(&cx, sizeof(cx));
  memzero(ivCopy, sizeof(ivCopy));
  if (rc != EXIT_SUCCESS) {
    throw jsi::JSError(rt, "aes_256_cbc_encrypt: encryption failed");
  }
  return wrapDigest(rt, std::move(buf));
}

jsi::Value invoke_aes_256_cbc_decrypt(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto key = requireArrayBufferAt(rt, "aes_256_cbc_decrypt", "key", args, count, 0);
  auto iv = requireArrayBufferAt(rt, "aes_256_cbc_decrypt", "iv", args, count, 1);
  auto data = requireArrayBufferAt(rt, "aes_256_cbc_decrypt", "data", args, count, 2);
  auto padStr = requireStringAt(rt, "aes_256_cbc_decrypt", "padding", args, count, 3);
  auto padding = parsePadding(rt, "aes_256_cbc_decrypt", padStr);

  if (key.size(rt) != kAesKey) {
    throw jsi::JSError(rt, "aes_256_cbc_decrypt: key must be 32 bytes");
  }
  if (iv.size(rt) != kAesBlock) {
    throw jsi::JSError(rt, "aes_256_cbc_decrypt: iv must be 16 bytes");
  }
  size_t inLen = data.size(rt);
  if (inLen == 0 || inLen % kAesBlock != 0) {
    throw jsi::JSError(
      rt, "aes_256_cbc_decrypt: data length must be a positive multiple of 16");
  }

  std::vector<uint8_t> buf(inLen);
  aes_decrypt_ctx cx;
  if (aes_decrypt_key256(key.data(rt), &cx) != EXIT_SUCCESS) {
    memzero(&cx, sizeof(cx));
    throw jsi::JSError(rt, "aes_256_cbc_decrypt: key schedule failed");
  }
  uint8_t ivCopy[kAesBlock];
  std::memcpy(ivCopy, iv.data(rt), kAesBlock);
  int rc = aes_cbc_decrypt(data.data(rt), buf.data(), static_cast<int>(inLen), ivCopy, &cx);
  memzero(&cx, sizeof(cx));
  memzero(ivCopy, sizeof(ivCopy));
  if (rc != EXIT_SUCCESS) {
    throw jsi::JSError(rt, "aes_256_cbc_decrypt: decryption failed");
  }

  if (padding == CbcPadding::Pkcs7) {
    // Constant-time PKCS#7 validation to prevent padding oracle attacks.
    uint8_t padByte = buf[inLen - 1];
    // Build a flag: valid iff padByte in [1..kAesBlock].
    unsigned bad = 0;
    bad |= (padByte == 0) ? 1u : 0u;
    bad |= (padByte > kAesBlock) ? 1u : 0u;
    // Check all padding bytes match — always inspect a full block to keep
    // the loop count independent of padByte.
    for (size_t i = 0; i < kAesBlock; i++) {
      // shouldCheck is 1 when this index falls within the padding region
      unsigned shouldCheck = (i < padByte) ? 1u : 0u;
      unsigned mismatch = (buf[inLen - 1 - i] != padByte) ? 1u : 0u;
      bad |= shouldCheck & mismatch;
    }
    if (bad) {
      memzero(buf.data(), buf.size());
      throw jsi::JSError(rt, "aes_256_cbc_decrypt: invalid PKCS#7 padding");
    }
    buf.resize(inLen - padByte);
  }
  return wrapDigest(rt, std::move(buf));
}

// --- AES-256-CTR -----------------------------------------------------------
// CTR is symmetric — one primitive covers both encrypt and decrypt.

jsi::Value invoke_aes_256_ctr_crypt(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto key = requireArrayBufferAt(rt, "aes_256_ctr_crypt", "key", args, count, 0);
  auto iv = requireArrayBufferAt(rt, "aes_256_ctr_crypt", "iv", args, count, 1);
  auto data = requireArrayBufferAt(rt, "aes_256_ctr_crypt", "data", args, count, 2);

  if (key.size(rt) != kAesKey) {
    throw jsi::JSError(rt, "aes_256_ctr_crypt: key must be 32 bytes");
  }
  if (iv.size(rt) != kAesBlock) {
    throw jsi::JSError(rt, "aes_256_ctr_crypt: iv must be 16 bytes");
  }
  size_t inLen = data.size(rt);
  std::vector<uint8_t> buf(inLen);

  aes_encrypt_ctx cx;
  if (aes_encrypt_key256(key.data(rt), &cx) != EXIT_SUCCESS) {
    memzero(&cx, sizeof(cx));
    throw jsi::JSError(rt, "aes_256_ctr_crypt: key schedule failed");
  }
  // Counter buffer is updated in-place by aes_ctr_crypt; we feed a copy
  // so the caller's iv argument is left untouched.
  uint8_t cbuf[kAesBlock];
  std::memcpy(cbuf, iv.data(rt), kAesBlock);
  int rc = aes_ctr_crypt(
    data.data(rt), buf.data(), static_cast<int>(inLen), cbuf, aes_ctr_cbuf_inc, &cx);
  memzero(&cx, sizeof(cx));
  memzero(cbuf, sizeof(cbuf));
  if (rc != EXIT_SUCCESS) {
    throw jsi::JSError(rt, "aes_256_ctr_crypt: crypt failed");
  }
  return wrapDigest(rt, std::move(buf));
}

// --- AES-256-GCM -----------------------------------------------------------

// Returns the full ciphertext concatenated with the 16-byte tag so the
// JS side only crosses the JSI boundary once. aad may be null/undefined.
jsi::Value invoke_aes_256_gcm_encrypt(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto key = requireArrayBufferAt(rt, "aes_256_gcm_encrypt", "key", args, count, 0);
  auto nonce = requireArrayBufferAt(rt, "aes_256_gcm_encrypt", "nonce", args, count, 1);
  auto plaintext = requireArrayBufferAt(rt, "aes_256_gcm_encrypt", "plaintext", args, count, 2);

  if (key.size(rt) != kAesKey) {
    throw jsi::JSError(rt, "aes_256_gcm_encrypt: key must be 32 bytes");
  }
  size_t nonceLen = nonce.size(rt);
  if (nonceLen == 0) {
    throw jsi::JSError(rt, "aes_256_gcm_encrypt: nonce must be non-empty");
  }

  const uint8_t* aadPtr = nullptr;
  size_t aadLen = 0;
  if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
    auto aad = requireArrayBufferAt(rt, "aes_256_gcm_encrypt", "aad", args, count, 3);
    aadPtr = aad.data(rt);
    aadLen = aad.size(rt);
  }

  size_t ptLen = plaintext.size(rt);
  std::vector<uint8_t> out(ptLen + kGcmTag);
  if (ptLen) std::memcpy(out.data(), plaintext.data(rt), ptLen);

  gcm_ctx ctx;
  if (gcm_init_and_key(key.data(rt), kAesKey, &ctx) != RETURN_GOOD) {
    memzero(&ctx, sizeof(ctx));
    throw jsi::JSError(rt, "aes_256_gcm_encrypt: init failed");
  }
  int rc = gcm_encrypt_message(
    nonce.data(rt), static_cast<unsigned long>(nonceLen),
    aadPtr, static_cast<unsigned long>(aadLen),
    out.data(), static_cast<unsigned long>(ptLen),
    out.data() + ptLen, kGcmTag,
    &ctx);
  gcm_end(&ctx);
  memzero(&ctx, sizeof(ctx));
  if (rc != RETURN_GOOD) {
    throw jsi::JSError(rt, "aes_256_gcm_encrypt: encryption failed");
  }
  return wrapDigest(rt, std::move(out));
}

// Input is ciphertext || tag(16). Throws on tag mismatch (matches the
// WebCrypto / node:crypto decipher behaviour).
jsi::Value invoke_aes_256_gcm_decrypt(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto key = requireArrayBufferAt(rt, "aes_256_gcm_decrypt", "key", args, count, 0);
  auto nonce = requireArrayBufferAt(rt, "aes_256_gcm_decrypt", "nonce", args, count, 1);
  auto sealed = requireArrayBufferAt(rt, "aes_256_gcm_decrypt", "sealed", args, count, 2);

  if (key.size(rt) != kAesKey) {
    throw jsi::JSError(rt, "aes_256_gcm_decrypt: key must be 32 bytes");
  }
  size_t nonceLen = nonce.size(rt);
  if (nonceLen == 0) {
    throw jsi::JSError(rt, "aes_256_gcm_decrypt: nonce must be non-empty");
  }
  size_t sealedLen = sealed.size(rt);
  if (sealedLen < kGcmTag) {
    throw jsi::JSError(rt, "aes_256_gcm_decrypt: sealed input shorter than tag");
  }

  const uint8_t* aadPtr = nullptr;
  size_t aadLen = 0;
  if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
    auto aad = requireArrayBufferAt(rt, "aes_256_gcm_decrypt", "aad", args, count, 3);
    aadPtr = aad.data(rt);
    aadLen = aad.size(rt);
  }

  size_t ctLen = sealedLen - kGcmTag;
  std::vector<uint8_t> buf(ctLen);
  if (ctLen) std::memcpy(buf.data(), sealed.data(rt), ctLen);

  gcm_ctx ctx;
  if (gcm_init_and_key(key.data(rt), kAesKey, &ctx) != RETURN_GOOD) {
    memzero(&ctx, sizeof(ctx));
    throw jsi::JSError(rt, "aes_256_gcm_decrypt: init failed");
  }
  int rc = gcm_decrypt_message(
    nonce.data(rt), static_cast<unsigned long>(nonceLen),
    aadPtr, static_cast<unsigned long>(aadLen),
    buf.data(), static_cast<unsigned long>(ctLen),
    sealed.data(rt) + ctLen, kGcmTag,
    &ctx);
  gcm_end(&ctx);
  memzero(&ctx, sizeof(ctx));
  if (rc != RETURN_GOOD) {
    // Zero the partially-decrypted buffer before bubbling up so we don't
    // leak unauthenticated plaintext through the exception path.
    if (!buf.empty()) memzero(buf.data(), buf.size());
    throw jsi::JSError(rt, "aes_256_gcm_decrypt: authentication failed");
  }
  return wrapDigest(rt, std::move(buf));
}

} // namespace

void registerAesMethods(MethodMap& map) {
  map.push_back({"aes_256_cbc_encrypt", 4, invoke_aes_256_cbc_encrypt});
  map.push_back({"aes_256_cbc_decrypt", 4, invoke_aes_256_cbc_decrypt});
  map.push_back({"aes_256_ctr_crypt",   3, invoke_aes_256_ctr_crypt});
  map.push_back({"aes_256_gcm_encrypt", 4, invoke_aes_256_gcm_encrypt});
  map.push_back({"aes_256_gcm_decrypt", 4, invoke_aes_256_gcm_decrypt});
}

}

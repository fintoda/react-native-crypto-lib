#include "SecureKVPassphrase.h"
#include "SecureKVSlot.h"

#include <cstdlib>   // arc4random_buf
#include <cstring>
#include <stdexcept>

extern "C" {
#include "aes/aes.h"
#include "aes/aesgcm.h"
#include "hmac.h"
#include "memzero.h"
#include "pbkdf2.h"
}

namespace facebook::react::cryptolib {
namespace {

// Constant-time byte comparison. Returns true iff the inputs are equal.
// Used for the KCV verifier check to avoid leaking how many bytes match
// (not strictly required for KCV under our threat model, but cheap and
// removes a footgun if the same primitive is reused elsewhere).
bool ctEquals(const uint8_t* a, const uint8_t* b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

void writeU32BE(uint8_t* out, uint32_t v) {
  out[0] = static_cast<uint8_t>((v >> 24) & 0xff);
  out[1] = static_cast<uint8_t>((v >> 16) & 0xff);
  out[2] = static_cast<uint8_t>((v >> 8) & 0xff);
  out[3] = static_cast<uint8_t>(v & 0xff);
}

uint32_t readU32BE(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

// PBKDF2-HMAC-SHA512 producing 64 bytes split into aes_key||hmac_key.
// On any failure throws std::runtime_error and zeroes the output buffer.
void deriveKeys(
  const std::string& passphrase,
  const uint8_t* salt, size_t saltLen,
  uint32_t iters,
  uint8_t aesKey[kAesKeyLen],
  uint8_t hmacKey[kHmacKeyLen]
) {
  uint8_t derived[kAesKeyLen + kHmacKeyLen];
  pbkdf2_hmac_sha512(
    reinterpret_cast<const uint8_t*>(passphrase.data()),
    static_cast<int>(passphrase.size()),
    salt, static_cast<int>(saltLen),
    iters,
    derived, static_cast<int>(sizeof(derived)));
  std::memcpy(aesKey, derived, kAesKeyLen);
  std::memcpy(hmacKey, derived + kAesKeyLen, kHmacKeyLen);
  memzero(derived, sizeof(derived));
}

// verifier = HMAC-SHA256(hmac_key, kVerifierLabel)[0..kVerifierLen]
void computeVerifier(
  const uint8_t hmacKey[kHmacKeyLen],
  uint8_t verifierOut[kVerifierLen]
) {
  uint8_t macFull[32];
  hmac_sha256(
    hmacKey, static_cast<uint32_t>(kHmacKeyLen),
    reinterpret_cast<const uint8_t*>(kVerifierLabel),
    static_cast<uint32_t>(std::strlen(kVerifierLabel)),
    macFull);
  std::memcpy(verifierOut, macFull, kVerifierLen);
  memzero(macFull, sizeof(macFull));
}

}  // namespace

std::vector<uint8_t> wrapPassphraseEnvelope(
  const uint8_t* innerSlot,
  size_t innerLen,
  const std::string& passphrase,
  uint32_t iters
) {
  if (passphrase.empty()) {
    throw std::runtime_error("backup: passphrase must be non-empty");
  }
  if (iters < kKdfMinIters || iters > kKdfMaxIters) {
    throw std::runtime_error("backup: iterations out of range");
  }

  // Build envelope buffer. Layout at offsets:
  //   [0]  tag
  //   [1]  version
  //   [2]  iters BE
  //   [6]  salt
  //   [22] IV
  //   [34] verifier
  //   [50] ciphertext
  //   [50+N] GCM tag
  std::vector<uint8_t> out(kEnvelopeHeaderLen + innerLen + kGcmTagLen);
  out[0] = static_cast<uint8_t>(SlotKind::PassphraseWrapped);
  out[1] = kEnvVersion;
  writeU32BE(out.data() + 2, iters);
  uint8_t* salt = out.data() + 6;
  uint8_t* iv = out.data() + 6 + kSaltLen;
  uint8_t* verifier = out.data() + 6 + kSaltLen + kIvLen;
  uint8_t* ciphertext = out.data() + kEnvelopeHeaderLen;
  uint8_t* tag = ciphertext + innerLen;

  arc4random_buf(salt, kSaltLen);
  arc4random_buf(iv, kIvLen);

  uint8_t aesKey[kAesKeyLen];
  uint8_t hmacKey[kHmacKeyLen];

  try {
    deriveKeys(passphrase, salt, kSaltLen, iters, aesKey, hmacKey);
    computeVerifier(hmacKey, verifier);
  } catch (...) {
    memzero(aesKey, sizeof(aesKey));
    memzero(hmacKey, sizeof(hmacKey));
    memzero(out.data(), out.size());
    throw;
  }

  // Copy plaintext into ciphertext region (gcm_encrypt_message works
  // in-place on the buffer it's given).
  if (innerLen > 0) std::memcpy(ciphertext, innerSlot, innerLen);

  // AAD covers tag + version + iters + verifier (22 bytes).
  const uint8_t* aad = out.data();
  size_t aadLen = 1 + 1 + 4 + kVerifierLen;
  // ...but verifier sits after salt+iv, so AAD isn't contiguous. We need
  // to assemble it.
  std::vector<uint8_t> aadBuf(aadLen);
  aadBuf[0] = out[0];
  aadBuf[1] = out[1];
  std::memcpy(aadBuf.data() + 2, out.data() + 2, 4);
  std::memcpy(aadBuf.data() + 6, verifier, kVerifierLen);
  aad = aadBuf.data();

  gcm_ctx ctx;
  if (gcm_init_and_key(aesKey, kAesKeyLen, &ctx) != RETURN_GOOD) {
    memzero(&ctx, sizeof(ctx));
    memzero(aesKey, sizeof(aesKey));
    memzero(hmacKey, sizeof(hmacKey));
    memzero(out.data(), out.size());
    throw std::runtime_error("backup: GCM init failed");
  }
  int rc = gcm_encrypt_message(
    iv, static_cast<unsigned long>(kIvLen),
    aad, static_cast<unsigned long>(aadLen),
    ciphertext, static_cast<unsigned long>(innerLen),
    tag, static_cast<unsigned long>(kGcmTagLen),
    &ctx);
  gcm_end(&ctx);
  memzero(&ctx, sizeof(ctx));
  memzero(aesKey, sizeof(aesKey));
  memzero(hmacKey, sizeof(hmacKey));

  if (rc != RETURN_GOOD) {
    memzero(out.data(), out.size());
    throw std::runtime_error("backup: GCM encrypt failed");
  }
  return out;
}

std::vector<uint8_t> unwrapPassphraseEnvelope(
  const uint8_t* envelope,
  size_t envelopeLen,
  const std::string& passphrase
) {
  if (envelopeLen < kEnvelopeMinLen) {
    throw std::runtime_error("backup: envelope truncated");
  }
  if (envelope[0] != static_cast<uint8_t>(SlotKind::PassphraseWrapped)) {
    throw std::runtime_error("backup: envelope slot tag mismatch");
  }
  if (envelope[1] != kEnvVersion) {
    throw std::runtime_error("backup: unsupported envelope version");
  }
  uint32_t iters = readU32BE(envelope + 2);
  if (iters < kKdfMinIters || iters > kKdfMaxIters) {
    throw std::runtime_error("backup: iterations out of range");
  }
  if (passphrase.empty()) {
    throw std::runtime_error("passphrase: required");
  }

  const uint8_t* salt = envelope + 6;
  const uint8_t* iv = envelope + 6 + kSaltLen;
  const uint8_t* verifier = envelope + 6 + kSaltLen + kIvLen;
  const uint8_t* ciphertext = envelope + kEnvelopeHeaderLen;
  size_t innerLen = envelopeLen - kEnvelopeHeaderLen - kGcmTagLen;
  const uint8_t* tag = ciphertext + innerLen;

  uint8_t aesKey[kAesKeyLen];
  uint8_t hmacKey[kHmacKeyLen];
  uint8_t expected[kVerifierLen];

  try {
    deriveKeys(passphrase, salt, kSaltLen, iters, aesKey, hmacKey);
    computeVerifier(hmacKey, expected);
  } catch (...) {
    memzero(aesKey, sizeof(aesKey));
    memzero(hmacKey, sizeof(hmacKey));
    memzero(expected, sizeof(expected));
    throw;
  }

  if (!ctEquals(verifier, expected, kVerifierLen)) {
    memzero(aesKey, sizeof(aesKey));
    memzero(hmacKey, sizeof(hmacKey));
    memzero(expected, sizeof(expected));
    throw std::runtime_error("passphrase: wrong");
  }
  memzero(expected, sizeof(expected));

  // Reassemble AAD = [tag][version][iters][verifier] (22 bytes).
  uint8_t aad[1 + 1 + 4 + kVerifierLen];
  aad[0] = envelope[0];
  aad[1] = envelope[1];
  std::memcpy(aad + 2, envelope + 2, 4);
  std::memcpy(aad + 6, verifier, kVerifierLen);

  std::vector<uint8_t> plaintext(innerLen);
  if (innerLen > 0) std::memcpy(plaintext.data(), ciphertext, innerLen);

  gcm_ctx ctx;
  if (gcm_init_and_key(aesKey, kAesKeyLen, &ctx) != RETURN_GOOD) {
    memzero(&ctx, sizeof(ctx));
    memzero(aesKey, sizeof(aesKey));
    memzero(hmacKey, sizeof(hmacKey));
    memzero(plaintext.data(), plaintext.size());
    throw std::runtime_error("backup: GCM init failed");
  }
  int rc = gcm_decrypt_message(
    iv, static_cast<unsigned long>(kIvLen),
    aad, static_cast<unsigned long>(sizeof(aad)),
    plaintext.data(), static_cast<unsigned long>(innerLen),
    tag, static_cast<unsigned long>(kGcmTagLen),
    &ctx);
  gcm_end(&ctx);
  memzero(&ctx, sizeof(ctx));
  memzero(aesKey, sizeof(aesKey));
  memzero(hmacKey, sizeof(hmacKey));
  memzero(aad, sizeof(aad));

  if (rc != RETURN_GOOD) {
    // Verifier matched, so the passphrase is correct — this means the
    // ciphertext / tag / AAD has been tampered with or the storage
    // corrupted. Distinct from WrongPassphraseError on the JS side.
    memzero(plaintext.data(), plaintext.size());
    throw std::runtime_error("backup: data integrity check failed");
  }
  return plaintext;
}

}  // namespace facebook::react::cryptolib

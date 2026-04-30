#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Passphrase-wrap envelope format (slot kind 0x03, see SecureKVSlot.h).
//
//   [1B  0x03 = SlotKind::PassphraseWrapped]
//   [1B  envelope version = 0x01]
//   [4B  iters BE]                  PBKDF2 iteration count
//   [16B salt]                      csprng per wrap
//   [12B IV]                        csprng per wrap
//   [16B verifier]                  HMAC-SHA256(hmac_key, kVerifierLabel)[0..16]
//   [N   ciphertext]                AES-256-GCM(inner-slot-bytes)
//   [16B GCM tag]
//
// KDF: pbkdf2_hmac_sha512(passphrase_utf8, salt, iters) -> 64 bytes.
// Split: aes_key = derived[0..32], hmac_key = derived[32..64].
//
// Verifier purpose: distinguish "wrong passphrase" from "data corruption".
// On unwrap, the expected verifier is recomputed from hmac_key and compared
// constant-time before any AES-GCM attempt. Mismatch -> wrong passphrase
// (definitive). Match + subsequent GCM auth failure -> data corruption.
//
// AAD covers [tag][version][iters][verifier] (22 bytes). Salt and IV are
// authenticated implicitly through the derived key (changing them yields a
// different aes_key, which fails GCM auth).
//
// All sensitive intermediates (derived bytes, aes_key, hmac_key, gcm ctx)
// are memzero'd on every code path including throws.

namespace facebook::react::cryptolib {

constexpr uint8_t kEnvVersion = 0x01;
constexpr size_t kSaltLen = 16;
constexpr size_t kIvLen = 12;
constexpr size_t kVerifierLen = 16;
constexpr size_t kGcmTagLen = 16;
constexpr size_t kAesKeyLen = 32;
constexpr size_t kHmacKeyLen = 32;

// Header up to and including verifier (everything before ciphertext):
//   tag(1) + version(1) + iters(4) + salt(16) + iv(12) + verifier(16) = 50
constexpr size_t kEnvelopeHeaderLen =
  1 + 1 + 4 + kSaltLen + kIvLen + kVerifierLen;

// Minimum envelope size: header + GCM tag (ciphertext can legitimately be
// zero bytes if the inner slot is empty, though wrapping a zero-length
// inner is a caller bug — we still parse correctly).
constexpr size_t kEnvelopeMinLen = kEnvelopeHeaderLen + kGcmTagLen;

constexpr uint32_t kKdfMinIters = 100'000;
constexpr uint32_t kKdfMaxIters = 10'000'000;
constexpr uint32_t kKdfDefaultIters = 600'000;

// Domain-separation label for the verifier KCV. Bumping the version
// suffix invalidates older verifiers — used if envelope format changes.
inline constexpr const char* kVerifierLabel = "secureKV.passphrase.v1";

// Wrap a plaintext slot blob into a PassphraseWrapped envelope.
//
// `innerSlot` is the inner slot bytes (e.g. `[0x01][seed_bytes]` for a seed
// slot) — the function does NOT prepend a slot tag, the caller passes in
// the bytes that belong inside the GCM ciphertext.
//
// Throws std::runtime_error on:
//   - iters out of range [kKdfMinIters, kKdfMaxIters]
//   - empty passphrase
//   - PBKDF2 / GCM init / GCM encrypt failure (vendor library error)
//
// Returned vector starts with `0x03` (SlotKind::PassphraseWrapped tag) so
// the result is itself a valid slot byte stream.
std::vector<uint8_t> wrapPassphraseEnvelope(
  const uint8_t* innerSlot,
  size_t innerLen,
  const std::string& passphrase,
  uint32_t iters);

// Unwrap a PassphraseWrapped envelope and return the inner slot bytes.
//
// `envelope` must start with the 0x03 tag and be at least kEnvelopeMinLen
// bytes long; on the success path the returned vector matches the original
// `innerSlot` argument that produced this envelope.
//
// Throws std::runtime_error with one of these reason prefixes:
//   - "backup: ..."         — malformed envelope (size, version, iters)
//   - "passphrase: wrong"   — verifier mismatch (wrong passphrase)
//   - "backup: data integrity check failed" — verifier matched but GCM
//                              auth failed, indicating tampering or
//                              storage corruption
std::vector<uint8_t> unwrapPassphraseEnvelope(
  const uint8_t* envelope,
  size_t envelopeLen,
  const std::string& passphrase);

}  // namespace facebook::react::cryptolib

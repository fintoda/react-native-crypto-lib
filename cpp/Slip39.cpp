#include "Common.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

extern "C" {
#include "memzero.h"
#include "pbkdf2.h"
#include "shamir.h"
#include "slip39.h"
}

namespace facebook::react::cryptolib {
namespace {

// ---------------------------------------------------------------------------
// SLIP-39 constants
// ---------------------------------------------------------------------------

constexpr size_t kRadixBits = 10;
constexpr size_t kChecksumLenWords = 3;

constexpr size_t kMinSecretLen = 16;
constexpr size_t kMaxSecretLen = SHAMIR_MAX_LEN; // 32
constexpr size_t kFeistelRounds = 4;
constexpr uint32_t kBaseIterCount = 10000;
constexpr uint8_t kMaxShareCount = 16;
constexpr uint8_t kMaxGroupCount = 16;
constexpr uint8_t kSecretIndex = 255; // x-coordinate for the shared secret in Shamir

// Customization string for RS1024 checksum
static const uint16_t kCustomizationString[] = {
  's', 'h', 'a', 'm', 'i', 'r'
};
constexpr size_t kCustomizationLen = 6;

// RS1024 generator polynomial coefficients (from SLIP-39 spec)
static const uint32_t kRS1024Gen[5] = {
  0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009
};

// ---------------------------------------------------------------------------
// RS1024 checksum
// ---------------------------------------------------------------------------

static uint32_t rs1024_polymod(const std::vector<uint16_t>& values) {
  uint32_t chk = 1;
  for (auto v : values) {
    uint32_t b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10) ^ v;
    for (int i = 0; i < 5; i++) {
      if ((b >> i) & 1) {
        chk ^= kRS1024Gen[i];
      }
    }
  }
  return chk;
}

static std::vector<uint16_t> rs1024_create_checksum(
    const std::vector<uint16_t>& data) {
  std::vector<uint16_t> values;
  values.reserve(kCustomizationLen + data.size() + kChecksumLenWords);
  for (size_t i = 0; i < kCustomizationLen; i++) {
    values.push_back(kCustomizationString[i]);
  }
  values.insert(values.end(), data.begin(), data.end());
  for (size_t i = 0; i < kChecksumLenWords; i++) {
    values.push_back(0);
  }
  uint32_t polymod = rs1024_polymod(values) ^ 1;
  std::vector<uint16_t> result(kChecksumLenWords);
  for (size_t i = 0; i < kChecksumLenWords; i++) {
    result[i] = static_cast<uint16_t>(
      (polymod >> (kRadixBits * (kChecksumLenWords - 1 - i))) & 0x3FF);
  }
  return result;
}

static bool rs1024_verify_checksum(const std::vector<uint16_t>& data) {
  std::vector<uint16_t> values;
  values.reserve(kCustomizationLen + data.size());
  for (size_t i = 0; i < kCustomizationLen; i++) {
    values.push_back(kCustomizationString[i]);
  }
  values.insert(values.end(), data.begin(), data.end());
  return rs1024_polymod(values) == 1;
}

// ---------------------------------------------------------------------------
// Bit packing: bytes <-> 10-bit words
// ---------------------------------------------------------------------------

static std::vector<uint16_t> bytes_to_words(
    const uint8_t* data, size_t len) {
  // SLIP-39 treats the byte array as a big-endian integer and extracts
  // 10-bit words from MSB to LSB. Padding zeros are at the MSB of word[0].
  size_t totalBits = len * 8;
  size_t wordCount = (totalBits + kRadixBits - 1) / kRadixBits;
  size_t padding = wordCount * kRadixBits - totalBits;
  std::vector<uint16_t> words(wordCount, 0);
  for (size_t i = 0; i < totalBits; i++) {
    size_t byteIdx = i / 8;
    size_t bitIdx = 7 - (i % 8);
    if ((data[byteIdx] >> bitIdx) & 1) {
      size_t globalPos = i + padding;
      size_t wordIdx = globalPos / kRadixBits;
      size_t wordBit = kRadixBits - 1 - (globalPos % kRadixBits);
      words[wordIdx] |= (1 << wordBit);
    }
  }
  return words;
}

static std::vector<uint8_t> words_to_bytes(
    const uint16_t* words, size_t wordCount, size_t byteLen) {
  // Inverse of bytes_to_words: skip the MSB padding bits, then unpack.
  std::vector<uint8_t> result(byteLen, 0);
  size_t totalBits = byteLen * 8;
  size_t padding = wordCount * kRadixBits - totalBits;
  for (size_t i = 0; i < totalBits; i++) {
    size_t globalPos = i + padding;
    size_t wordIdx = globalPos / kRadixBits;
    size_t wordBit = kRadixBits - 1 - (globalPos % kRadixBits);
    if (wordIdx < wordCount && ((words[wordIdx] >> wordBit) & 1)) {
      size_t byteIdx = i / 8;
      size_t bitIdx = 7 - (i % 8);
      result[byteIdx] |= (1 << bitIdx);
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// SLIP-39 header encoding/decoding
// ---------------------------------------------------------------------------

struct ShareHeader {
  uint16_t id;
  uint8_t iterationExponent;
  uint8_t groupIndex;
  uint8_t groupThreshold;
  uint8_t groupCount;
  uint8_t memberIndex;
  uint8_t memberThreshold;
};

// Encode header fields + share value into a word sequence (without checksum).
static std::vector<uint16_t> encode_share(
    const ShareHeader& h,
    const uint8_t* shareValue,
    size_t shareLen) {
  // Header: id(15) | iter_exp(4) | group_idx(4) | group_thr(4) |
  //         group_cnt(4) | member_idx(4) | member_thr(4) = 39 bits
  // Packed into 4 10-bit words (1 padding bit at MSB of word[0]).
  // Then: share value bytes as 10-bit words.
  // Then: 3 checksum words.

  size_t shareWordCount = (shareLen * 8 + kRadixBits - 1) / kRadixBits;
  size_t totalWords = 4 + shareWordCount; // 4 header words + share words

  std::vector<uint16_t> data(totalWords);

  // Pack 39-bit header into 4 10-bit words. SLIP-39 treats the header as a
  // big integer and extracts 10-bit words MSB-first, so padding is at the
  // MSB of word[0] (same as _int_to_indices in the reference implementation).
  uint64_t headerBits =
    (static_cast<uint64_t>(h.id) << 24) |
    (static_cast<uint64_t>(h.iterationExponent) << 20) |
    (static_cast<uint64_t>(h.groupIndex) << 16) |
    (static_cast<uint64_t>(h.groupThreshold - 1) << 12) |
    (static_cast<uint64_t>(h.groupCount - 1) << 8) |
    (static_cast<uint64_t>(h.memberIndex) << 4) |
    (static_cast<uint64_t>(h.memberThreshold - 1));

  data[0] = static_cast<uint16_t>((headerBits >> 30) & 0x3FF);
  data[1] = static_cast<uint16_t>((headerBits >> 20) & 0x3FF);
  data[2] = static_cast<uint16_t>((headerBits >> 10) & 0x3FF);
  data[3] = static_cast<uint16_t>(headerBits & 0x3FF);

  // Pack share value into remaining words
  auto shareWords = bytes_to_words(shareValue, shareLen);
  for (size_t i = 0; i < shareWordCount && i < shareWords.size(); i++) {
    data[4 + i] = shareWords[i];
  }

  // Append checksum
  auto checksum = rs1024_create_checksum(data);
  data.insert(data.end(), checksum.begin(), checksum.end());

  return data;
}

static bool decode_share(
    const std::vector<uint16_t>& words,
    ShareHeader& h,
    std::vector<uint8_t>& shareValue) {
  if (words.size() < 4 + kChecksumLenWords + 1) {
    return false; // Too short
  }

  // Verify checksum
  if (!rs1024_verify_checksum(words)) {
    return false;
  }

  // Unpack header from first 4 words. The 39-bit header sits in the lower
  // 39 bits of the 40-bit value (padding zero is MSB of word[0]).
  uint64_t headerBits =
    (static_cast<uint64_t>(words[0]) << 30) |
    (static_cast<uint64_t>(words[1]) << 20) |
    (static_cast<uint64_t>(words[2]) << 10) |
    static_cast<uint64_t>(words[3]);

  h.id = static_cast<uint16_t>((headerBits >> 24) & 0x7FFF);
  h.iterationExponent = static_cast<uint8_t>((headerBits >> 20) & 0xF);
  h.groupIndex = static_cast<uint8_t>((headerBits >> 16) & 0xF);
  h.groupThreshold = static_cast<uint8_t>(((headerBits >> 12) & 0xF) + 1);
  h.groupCount = static_cast<uint8_t>(((headerBits >> 8) & 0xF) + 1);
  h.memberIndex = static_cast<uint8_t>((headerBits >> 4) & 0xF);
  h.memberThreshold = static_cast<uint8_t>((headerBits & 0xF) + 1);

  // Unpack share value from words after header, before checksum
  size_t shareWordCount = words.size() - 4 - kChecksumLenWords;
  // Share value length in bytes: the spec says the padded share value
  // is (total_words - 4 - 3) words, and the byte length is derived from
  // the 10-bit word count. SLIP-39 requires even byte lengths.
  size_t shareByteLen = (shareWordCount * kRadixBits) / 8;
  shareValue = words_to_bytes(words.data() + 4, shareWordCount, shareByteLen);

  return true;
}

// ---------------------------------------------------------------------------
// Mnemonic encoding/decoding
// ---------------------------------------------------------------------------

static std::string words_to_mnemonic(const std::vector<uint16_t>& words) {
  std::string result;
  for (size_t i = 0; i < words.size(); i++) {
    if (i > 0) result += ' ';
    const char* w = get_word(words[i]);
    if (w) result += w;
  }
  return result;
}

static bool mnemonic_to_words(const std::string& mnemonic,
                              std::vector<uint16_t>& words) {
  words.clear();
  std::istringstream iss(mnemonic);
  std::string token;
  while (iss >> token) {
    // SLIP-39 words are at most 8 characters; reject anything longer
    // to prevent uint8_t truncation in word_index().
    if (token.size() > 20) {
      return false;
    }
    uint16_t idx = 0;
    if (!word_index(&idx, token.c_str(), static_cast<uint8_t>(token.size()))) {
      return false;
    }
    words.push_back(idx);
  }
  return !words.empty();
}

// ---------------------------------------------------------------------------
// Feistel cipher for passphrase encryption (SLIP-39 spec)
// ---------------------------------------------------------------------------

static void slip39_encrypt(
    const uint8_t* masterSecret,
    size_t len,
    const std::string& passphrase,
    uint16_t id,
    uint8_t iterationExponent,
    uint8_t* encryptedOut) {
  uint32_t iterations = kBaseIterCount << iterationExponent;
  size_t half = len / 2;

  // L = first half, R = second half
  std::vector<uint8_t> L(masterSecret, masterSecret + half);
  std::vector<uint8_t> R(masterSecret + half, masterSecret + len);

  // Salt prefix: "shamir" + id (2 bytes big-endian)
  uint8_t saltPrefix[8] = {'s', 'h', 'a', 'm', 'i', 'r',
                            static_cast<uint8_t>(id >> 8),
                            static_cast<uint8_t>(id & 0xFF)};

  for (size_t round = 0; round < kFeistelRounds; round++) {
    // salt = saltPrefix + round_byte + R
    std::vector<uint8_t> salt(8 + 1 + R.size());
    memcpy(salt.data(), saltPrefix, 8);
    salt[8] = static_cast<uint8_t>(round);
    memcpy(salt.data() + 9, R.data(), R.size());

    // key = PBKDF2-HMAC-SHA256(passphrase, salt, iterations, half)
    std::vector<uint8_t> key(half);
    pbkdf2_hmac_sha256(
      reinterpret_cast<const uint8_t*>(passphrase.data()),
      static_cast<int>(passphrase.size()),
      salt.data(), static_cast<int>(salt.size()),
      iterations, key.data(), static_cast<int>(half));

    // newR = L ^ key; L = R; R = newR
    std::vector<uint8_t> newR(half);
    for (size_t i = 0; i < half; i++) {
      newR[i] = L[i] ^ key[i];
    }
    memzero(L.data(), L.size());
    L = R;
    memzero(R.data(), R.size());
    R = newR;
    memzero(newR.data(), newR.size());

    memzero(key.data(), key.size());
    memzero(salt.data(), salt.size());
  }

  // SLIP-39 outputs R||L (swapped) per spec
  memcpy(encryptedOut, R.data(), half);
  memcpy(encryptedOut + half, L.data(), half);

  memzero(L.data(), L.size());
  memzero(R.data(), R.size());
}

static void slip39_decrypt(
    const uint8_t* encryptedSecret,
    size_t len,
    const std::string& passphrase,
    uint16_t id,
    uint8_t iterationExponent,
    uint8_t* masterSecretOut) {
  uint32_t iterations = kBaseIterCount << iterationExponent;
  size_t half = len / 2;

  std::vector<uint8_t> L(encryptedSecret, encryptedSecret + half);
  std::vector<uint8_t> R(encryptedSecret + half, encryptedSecret + len);

  uint8_t saltPrefix[8] = {'s', 'h', 'a', 'm', 'i', 'r',
                            static_cast<uint8_t>(id >> 8),
                            static_cast<uint8_t>(id & 0xFF)};

  // SLIP-39 Feistel is self-inverse: decrypt uses the same round function
  // as encrypt, just with rounds in reverse order. Salt uses R (current
  // right half), matching the encrypt body.
  for (int round = kFeistelRounds - 1; round >= 0; round--) {
    std::vector<uint8_t> salt(8 + 1 + R.size());
    memcpy(salt.data(), saltPrefix, 8);
    salt[8] = static_cast<uint8_t>(round);
    memcpy(salt.data() + 9, R.data(), R.size());

    std::vector<uint8_t> key(half);
    pbkdf2_hmac_sha256(
      reinterpret_cast<const uint8_t*>(passphrase.data()),
      static_cast<int>(passphrase.size()),
      salt.data(), static_cast<int>(salt.size()),
      iterations, key.data(), static_cast<int>(half));

    // (L, R) = (R, L ^ key) — identical to encrypt step
    std::vector<uint8_t> newR(half);
    for (size_t i = 0; i < half; i++) {
      newR[i] = L[i] ^ key[i];
    }
    memzero(L.data(), L.size());
    L = R;
    memzero(R.data(), R.size());
    R = newR;
    memzero(newR.data(), newR.size());

    memzero(key.data(), key.size());
    memzero(salt.data(), salt.size());
  }

  // Output R||L (swapped), same as encrypt
  memcpy(masterSecretOut, R.data(), half);
  memcpy(masterSecretOut + half, L.data(), half);

  memzero(L.data(), L.size());
  memzero(R.data(), R.size());
}

// ---------------------------------------------------------------------------
// Shamir share generation (using shamir_interpolate from vendor)
// ---------------------------------------------------------------------------

// Generate `shareCount` shares of `secret` with the given threshold.
// Each share is `secretLen` bytes. Output is a flat array: shareCount * secretLen.
static bool generate_shares(
    uint8_t threshold,
    uint8_t shareCount,
    const uint8_t* secret,
    size_t secretLen,
    uint8_t* sharesOut) {
  if (threshold < 1 || threshold > shareCount || shareCount > kMaxShareCount) {
    return false;
  }
  if (secretLen > kMaxSecretLen || secretLen < kMinSecretLen) {
    return false;
  }

  // Special case: threshold == 1 means all shares are copies of the secret
  if (threshold == 1) {
    for (uint8_t i = 0; i < shareCount; i++) {
      memcpy(sharesOut + i * secretLen, secret, secretLen);
    }
    return true;
  }

  // A threshold-of-N scheme uses a polynomial of degree threshold-1.
  // We need threshold points to uniquely define it.
  // Points: (255, secret) + (0, random_0) + ... + (threshold-2, random_{threshold-2})
  // That gives us threshold points total: 1 (secret) + threshold-1 (random).
  // Then we interpolate at each output index to get the shares.
  uint8_t pointCount = threshold;
  std::vector<uint8_t> indices(pointCount);
  std::vector<std::vector<uint8_t>> values(pointCount,
                                            std::vector<uint8_t>(secretLen));
  std::vector<const uint8_t*> valuePtrs(pointCount);

  // Generate threshold-1 random points at indices 0..threshold-2
  for (uint8_t i = 0; i < threshold - 1; i++) {
    indices[i] = i;
    arc4random_buf(values[i].data(), secretLen);
    valuePtrs[i] = values[i].data();
  }
  // Secret at index 255
  indices[pointCount - 1] = kSecretIndex;
  memcpy(values[pointCount - 1].data(), secret, secretLen);
  valuePtrs[pointCount - 1] = values[pointCount - 1].data();

  // Now interpolate at each output index
  for (uint8_t i = 0; i < shareCount; i++) {
    if (i < threshold - 1) {
      // This share index is one of the random base points, just copy it
      memcpy(sharesOut + i * secretLen, values[i].data(), secretLen);
    } else {
      // Interpolate to get the share value at this index
      if (!shamir_interpolate(
            sharesOut + i * secretLen, i,
            indices.data(), valuePtrs.data(),
            pointCount, secretLen)) {
        // Clean up
        for (auto& v : values) memzero(v.data(), v.size());
        return false;
      }
    }
  }

  // Clean up sensitive data
  for (auto& v : values) memzero(v.data(), v.size());
  return true;
}

// ---------------------------------------------------------------------------
// JSI methods
// ---------------------------------------------------------------------------

jsi::Value invoke_slip39_generate(
    jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count) {
  auto secret = requireArrayBufferAt(
    rt, "slip39_generate", "masterSecret", args, count, 0);
  auto passphrase = requireStringAt(
    rt, "slip39_generate", "passphrase", args, count, 1);
  auto threshold = static_cast<uint8_t>(requireIntAt(
    rt, "slip39_generate", "threshold", args, count, 2, 1, kMaxShareCount));
  auto shareCount = static_cast<uint8_t>(requireIntAt(
    rt, "slip39_generate", "shareCount", args, count, 3, 1, kMaxShareCount));
  auto iterExp = static_cast<uint8_t>(requireIntAt(
    rt, "slip39_generate", "iterationExponent", args, count, 4, 0, 15));

  size_t secretLen = secret.size(rt);
  if (secretLen < kMinSecretLen || secretLen > kMaxSecretLen ||
      secretLen % 2 != 0) {
    throw jsi::JSError(
      rt, "slip39_generate: masterSecret must be 16-32 bytes, even length");
  }
  if (threshold > shareCount) {
    throw jsi::JSError(
      rt, "slip39_generate: threshold must be <= shareCount");
  }

  // Generate random 15-bit ID
  uint16_t id = 0;
  arc4random_buf(&id, sizeof(id));
  id &= 0x7FFF;

  // Encrypt master secret with passphrase
  std::vector<uint8_t> encrypted(secretLen);
  slip39_encrypt(secret.data(rt), secretLen, passphrase, id, iterExp,
                 encrypted.data());

  // Generate Shamir shares of the encrypted secret
  std::vector<uint8_t> shares(shareCount * secretLen);
  if (!generate_shares(threshold, shareCount, encrypted.data(), secretLen,
                       shares.data())) {
    memzero(encrypted.data(), encrypted.size());
    throw jsi::JSError(rt, "slip39_generate: share generation failed");
  }
  memzero(encrypted.data(), encrypted.size());

  // Encode each share as a mnemonic
  auto result = jsi::Array(rt, shareCount);
  for (uint8_t i = 0; i < shareCount; i++) {
    ShareHeader h{};
    h.id = id;
    h.iterationExponent = iterExp;
    h.groupIndex = 0;
    h.groupThreshold = 1;
    h.groupCount = 1;
    h.memberIndex = i;
    h.memberThreshold = threshold;

    auto wordSeq = encode_share(h, shares.data() + i * secretLen, secretLen);
    auto mnemonic = words_to_mnemonic(wordSeq);
    result.setValueAtIndex(rt, i, jsi::String::createFromUtf8(rt, mnemonic));
  }

  memzero(shares.data(), shares.size());
  return result;
}

jsi::Value invoke_slip39_combine(
    jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count) {
  // mnemonics are passed as a single string joined by '\n'
  auto mnemonicsStr = requireStringAt(
    rt, "slip39_combine", "mnemonics", args, count, 0);
  auto passphrase = requireStringAt(
    rt, "slip39_combine", "passphrase", args, count, 1);

  // Split by newline
  std::vector<std::string> mnemonics;
  std::istringstream iss(mnemonicsStr);
  std::string line;
  while (std::getline(iss, line, '\n')) {
    if (!line.empty()) {
      mnemonics.push_back(line);
    }
  }

  if (mnemonics.empty()) {
    throw jsi::JSError(rt, "slip39_combine: no mnemonics provided");
  }

  // Decode all mnemonics
  struct DecodedShare {
    ShareHeader header;
    std::vector<uint8_t> value;
  };
  std::vector<DecodedShare> decoded;
  decoded.reserve(mnemonics.size());

  for (auto& m : mnemonics) {
    std::vector<uint16_t> words;
    if (!mnemonic_to_words(m, words)) {
      throw jsi::JSError(rt, "slip39_combine: invalid mnemonic word");
    }
    DecodedShare ds{};
    if (!decode_share(words, ds.header, ds.value)) {
      throw jsi::JSError(rt, "slip39_combine: invalid share (checksum failed)");
    }
    decoded.push_back(std::move(ds));
  }

  // Helper to zero all decoded share values before throwing
  auto cleanDecoded = [&decoded]() {
    for (auto& ds : decoded) memzero(ds.value.data(), ds.value.size());
  };

  // Validate all headers match
  const auto& ref = decoded[0].header;
  for (size_t i = 1; i < decoded.size(); i++) {
    const auto& h = decoded[i].header;
    if (h.id != ref.id || h.iterationExponent != ref.iterationExponent ||
        h.groupThreshold != ref.groupThreshold ||
        h.groupCount != ref.groupCount) {
      cleanDecoded();
      throw jsi::JSError(
        rt, "slip39_combine: mismatched share headers (different set)");
    }
  }

  size_t secretLen = decoded[0].value.size();
  if (secretLen < kMinSecretLen || secretLen > kMaxSecretLen ||
      secretLen % 2 != 0) {
    cleanDecoded();
    throw jsi::JSError(
      rt, "slip39_combine: invalid share value length");
  }
  for (size_t i = 1; i < decoded.size(); i++) {
    if (decoded[i].value.size() != secretLen) {
      cleanDecoded();
      throw jsi::JSError(
        rt, "slip39_combine: mismatched share lengths");
    }
  }

  // Group shares by group_index
  struct GroupData {
    uint8_t memberThreshold;
    std::vector<uint8_t> memberIndices;
    std::vector<std::vector<uint8_t>> memberValues;
  };
  std::vector<GroupData> groups(ref.groupCount);
  for (auto& ds : decoded) {
    auto gi = ds.header.groupIndex;
    if (gi >= ref.groupCount) {
      cleanDecoded();
      throw jsi::JSError(rt, "slip39_combine: invalid group index");
    }
    groups[gi].memberThreshold = ds.header.memberThreshold;
    groups[gi].memberIndices.push_back(ds.header.memberIndex);
    groups[gi].memberValues.push_back(ds.value);
  }

  // Recover group secrets
  std::vector<uint8_t> groupIndices;
  std::vector<std::vector<uint8_t>> groupSecrets;

  for (uint8_t gi = 0; gi < ref.groupCount; gi++) {
    auto& g = groups[gi];
    if (g.memberIndices.empty()) continue;

    if (g.memberIndices.size() < g.memberThreshold) {
      cleanDecoded();
      throw jsi::JSError(
        rt, "slip39_combine: insufficient shares in group");
    }

    std::vector<uint8_t> groupSecret(secretLen);
    if (g.memberThreshold == 1) {
      // Threshold 1: share IS the group secret
      memcpy(groupSecret.data(), g.memberValues[0].data(), secretLen);
    } else {
      // Interpolate member shares to recover group secret
      std::vector<const uint8_t*> valuePtrs(g.memberIndices.size());
      for (size_t i = 0; i < g.memberIndices.size(); i++) {
        valuePtrs[i] = g.memberValues[i].data();
      }
      if (!shamir_interpolate(
            groupSecret.data(), kSecretIndex,
            g.memberIndices.data(), valuePtrs.data(),
            static_cast<uint8_t>(g.memberIndices.size()), secretLen)) {
        cleanDecoded();
        throw jsi::JSError(
          rt, "slip39_combine: Shamir interpolation failed (duplicate shares?)");
      }
    }
    groupIndices.push_back(gi);
    groupSecrets.push_back(std::move(groupSecret));
  }

  if (groupIndices.size() < ref.groupThreshold) {
    cleanDecoded();
    for (auto& gs : groupSecrets) memzero(gs.data(), gs.size());
    throw jsi::JSError(
      rt, "slip39_combine: insufficient groups for recovery");
  }

  // Recover the encrypted master secret from group secrets
  std::vector<uint8_t> encryptedSecret(secretLen);
  if (ref.groupThreshold == 1) {
    memcpy(encryptedSecret.data(), groupSecrets[0].data(), secretLen);
  } else {
    std::vector<const uint8_t*> groupValuePtrs(groupIndices.size());
    for (size_t i = 0; i < groupIndices.size(); i++) {
      groupValuePtrs[i] = groupSecrets[i].data();
    }
    if (!shamir_interpolate(
          encryptedSecret.data(), kSecretIndex,
          groupIndices.data(), groupValuePtrs.data(),
          static_cast<uint8_t>(groupIndices.size()), secretLen)) {
      cleanDecoded();
      for (auto& gs : groupSecrets) memzero(gs.data(), gs.size());
      throw jsi::JSError(
        rt, "slip39_combine: group-level interpolation failed");
    }
  }

  // Clean up group secrets
  for (auto& gs : groupSecrets) memzero(gs.data(), gs.size());

  // Decrypt with passphrase
  std::vector<uint8_t> masterSecret(secretLen);
  slip39_decrypt(encryptedSecret.data(), secretLen, passphrase,
                 ref.id, ref.iterationExponent, masterSecret.data());
  memzero(encryptedSecret.data(), encryptedSecret.size());

  // Clean up decoded share values
  for (auto& ds : decoded) memzero(ds.value.data(), ds.value.size());

  return wrapDigest(rt, std::move(masterSecret));
}

jsi::Value invoke_slip39_validate_mnemonic(
    jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count) {
  auto mnemonic = requireStringAt(
    rt, "slip39_validate_mnemonic", "mnemonic", args, count, 0);
  std::vector<uint16_t> words;
  if (!mnemonic_to_words(mnemonic, words)) {
    return jsi::Value(false);
  }
  if (words.size() < 4 + kChecksumLenWords + 1) {
    return jsi::Value(false);
  }
  return jsi::Value(rs1024_verify_checksum(words));
}

jsi::Value invoke_slip39_generate_groups(
    jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count) {
  auto secret = requireArrayBufferAt(
    rt, "slip39_generate_groups", "masterSecret", args, count, 0);
  auto passphrase = requireStringAt(
    rt, "slip39_generate_groups", "passphrase", args, count, 1);
  auto groupThreshold = static_cast<uint8_t>(requireIntAt(
    rt, "slip39_generate_groups", "groupThreshold", args, count, 2,
    1, kMaxGroupCount));
  // groups is an ArrayBuffer of packed uint8 pairs: [threshold, count, ...]
  auto groupsBuf = requireArrayBufferAt(
    rt, "slip39_generate_groups", "groups", args, count, 3);
  auto iterExp = static_cast<uint8_t>(requireIntAt(
    rt, "slip39_generate_groups", "iterationExponent", args, count, 4, 0, 15));

  size_t secretLen = secret.size(rt);
  if (secretLen < kMinSecretLen || secretLen > kMaxSecretLen ||
      secretLen % 2 != 0) {
    throw jsi::JSError(
      rt,
      "slip39_generate_groups: masterSecret must be 16-32 bytes, even length");
  }

  size_t groupsBufLen = groupsBuf.size(rt);
  if (groupsBufLen < 2 || groupsBufLen % 2 != 0) {
    throw jsi::JSError(
      rt, "slip39_generate_groups: groups must be packed uint8 pairs");
  }
  uint8_t groupCount = static_cast<uint8_t>(groupsBufLen / 2);
  if (groupCount > kMaxGroupCount) {
    throw jsi::JSError(rt, "slip39_generate_groups: too many groups (max 16)");
  }
  if (groupThreshold > groupCount) {
    throw jsi::JSError(
      rt, "slip39_generate_groups: groupThreshold must be <= group count");
  }

  struct GroupSpec {
    uint8_t threshold;
    uint8_t shareCount;
  };
  std::vector<GroupSpec> specs(groupCount);
  const uint8_t* gData = groupsBuf.data(rt);
  for (uint8_t i = 0; i < groupCount; i++) {
    specs[i].threshold = gData[i * 2];
    specs[i].shareCount = gData[i * 2 + 1];
    if (specs[i].threshold < 1 || specs[i].threshold > specs[i].shareCount ||
        specs[i].shareCount > kMaxShareCount) {
      throw jsi::JSError(
        rt, "slip39_generate_groups: invalid group spec");
    }
  }

  // Generate random 15-bit ID
  uint16_t id = 0;
  arc4random_buf(&id, sizeof(id));
  id &= 0x7FFF;

  // Encrypt master secret
  std::vector<uint8_t> encrypted(secretLen);
  slip39_encrypt(secret.data(rt), secretLen, passphrase, id, iterExp,
                 encrypted.data());

  // Split encrypted secret into group secrets
  std::vector<uint8_t> groupShares(groupCount * secretLen);
  if (!generate_shares(groupThreshold, groupCount, encrypted.data(), secretLen,
                       groupShares.data())) {
    memzero(encrypted.data(), encrypted.size());
    throw jsi::JSError(
      rt, "slip39_generate_groups: group share generation failed");
  }
  memzero(encrypted.data(), encrypted.size());

  // For each group, split the group secret into member shares
  auto result = jsi::Array(rt, groupCount);
  for (uint8_t gi = 0; gi < groupCount; gi++) {
    const uint8_t* groupSecret = groupShares.data() + gi * secretLen;
    auto& spec = specs[gi];

    std::vector<uint8_t> memberShares(spec.shareCount * secretLen);
    if (!generate_shares(spec.threshold, spec.shareCount, groupSecret,
                         secretLen, memberShares.data())) {
      memzero(groupShares.data(), groupShares.size());
      throw jsi::JSError(
        rt, "slip39_generate_groups: member share generation failed");
    }

    auto groupArr = jsi::Array(rt, spec.shareCount);
    for (uint8_t mi = 0; mi < spec.shareCount; mi++) {
      ShareHeader h{};
      h.id = id;
      h.iterationExponent = iterExp;
      h.groupIndex = gi;
      h.groupThreshold = groupThreshold;
      h.groupCount = groupCount;
      h.memberIndex = mi;
      h.memberThreshold = spec.threshold;

      auto wordSeq = encode_share(
        h, memberShares.data() + mi * secretLen, secretLen);
      auto mnemonic = words_to_mnemonic(wordSeq);
      groupArr.setValueAtIndex(
        rt, mi, jsi::String::createFromUtf8(rt, mnemonic));
    }
    memzero(memberShares.data(), memberShares.size());
    result.setValueAtIndex(rt, gi, std::move(groupArr));
  }

  memzero(groupShares.data(), groupShares.size());
  return result;
}

} // namespace

void registerSlip39Methods(MethodMap& map) {
  map.push_back({"slip39_generate",           5, invoke_slip39_generate});
  map.push_back({"slip39_generate_groups",    5, invoke_slip39_generate_groups});
  map.push_back({"slip39_combine",            2, invoke_slip39_combine});
  map.push_back({"slip39_validate_mnemonic",  1, invoke_slip39_validate_mnemonic});
}

}

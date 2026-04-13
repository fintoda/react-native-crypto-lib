#include "Common.h"

#include <cstdlib>
#include <cstring>

extern "C" {
#include "bip39.h"
#include "memzero.h"
}

namespace facebook::react::cryptolib {
namespace {

// BIP-39 allows 128/160/192/224/256-bit entropy, i.e. 12/15/18/21/24 words.
bool validEntropyLen(size_t len) {
  return len == 16 || len == 20 || len == 24 || len == 28 || len == 32;
}

jsi::Value invoke_bip39_from_entropy(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto entropy = requireArrayBuffer(rt, "bip39_from_entropy", args, count);
  size_t len = entropy.size(rt);
  if (!validEntropyLen(len)) {
    throw jsi::JSError(
      rt, "bip39_from_entropy: entropy must be 16, 20, 24, 28 or 32 bytes");
  }
  // mnemonic_from_data returns a pointer into a static internal buffer;
  // copy it out before calling mnemonic_clear.
  const char* mnemonic =
    mnemonic_from_data(entropy.data(rt), static_cast<int>(len));
  if (!mnemonic) {
    throw jsi::JSError(rt, "bip39_from_entropy: mnemonic generation failed");
  }
  std::string result = mnemonic;
  mnemonic_clear();
  return jsi::String::createFromUtf8(rt, result);
}

jsi::Value invoke_bip39_generate(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  double strength = requireIntAt(
    rt, "bip39_generate", "strength", args, count, 0, 128, 256);
  if (static_cast<int>(strength) % 32 != 0) {
    throw jsi::JSError(
      rt, "bip39_generate: strength must be 128, 160, 192, 224 or 256");
  }
  size_t entropyLen = static_cast<size_t>(strength) / 8;
  uint8_t entropy[32];
  arc4random_buf(entropy, entropyLen);
  const char* mnemonic =
    mnemonic_from_data(entropy, static_cast<int>(entropyLen));
  memzero(entropy, sizeof(entropy));
  if (!mnemonic) {
    throw jsi::JSError(rt, "bip39_generate: mnemonic generation failed");
  }
  std::string result = mnemonic;
  mnemonic_clear();
  return jsi::String::createFromUtf8(rt, result);
}

jsi::Value invoke_bip39_check(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto mnemonic = requireStringAt(rt, "bip39_check", "mnemonic", args, count, 0);
  return jsi::Value(mnemonic_check(mnemonic.c_str()) != 0);
}

jsi::Value invoke_bip39_to_seed(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto mnemonic = requireStringAt(rt, "bip39_to_seed", "mnemonic", args, count, 0);
  auto passphrase = requireStringAt(rt, "bip39_to_seed", "passphrase", args, count, 1);
  std::vector<uint8_t> out(64);
  // PBKDF2-HMAC-SHA512, 2048 iterations, salt = "mnemonic"+passphrase.
  mnemonic_to_seed(mnemonic.c_str(), passphrase.c_str(), out.data(), nullptr);
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerBip39Methods(MethodMap& map) {
  map.push_back({"bip39_generate",     1, invoke_bip39_generate});
  map.push_back({"bip39_from_entropy", 1, invoke_bip39_from_entropy});
  map.push_back({"bip39_check",        1, invoke_bip39_check});
  map.push_back({"bip39_to_seed",      2, invoke_bip39_to_seed});
}

}

#include "Common.h"

#include <cstdlib>

namespace facebook::react::cryptolib {
namespace {

// 1 MiB cap on a single RNG draw — not a hard crypto limit, just a sanity
// guard against accidentally allocating gigabytes from JS.
constexpr size_t kRngBytesMax = 1 << 20;

jsi::Value invoke_rng_bytes(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  if (count < 1 || !args[0].isNumber()) {
    throw jsi::JSError(rt, "rng_bytes: expected a number argument");
  }
  double n = args[0].asNumber();
  if (n < 0 || n > static_cast<double>(kRngBytesMax) ||
      n != static_cast<double>(static_cast<size_t>(n))) {
    throw jsi::JSError(rt, "rng_bytes: count must be an integer in [0, 1048576]");
  }
  std::vector<uint8_t> out(static_cast<size_t>(n));
  if (!out.empty()) {
    // arc4random_buf is the system CSPRNG on iOS and Android NDK (API 21+):
    // ChaCha20 reseeded from the kernel entropy pool, non-blocking, no fd
    // management required. Same call works on both platforms.
    arc4random_buf(out.data(), out.size());
  }
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerRngMethods(MethodMap& map) {
  map.push_back({"rng_bytes", 1, invoke_rng_bytes});
}

}

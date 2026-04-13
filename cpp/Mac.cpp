#include "Common.h"

extern "C" {
#include "hmac.h"
#include "sha2.h"
}

namespace facebook::react::cryptolib {
namespace {

jsi::Value invoke_hmac_sha256(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto key = requireArrayBufferAt(rt, "mac_hmac_sha256", "key", args, count, 0);
  auto msg = requireArrayBufferAt(rt, "mac_hmac_sha256", "msg", args, count, 1);
  if (key.size(rt) > UINT32_MAX) {
    throw jsi::JSError(rt, "mac_hmac_sha256: key too large");
  }
  if (msg.size(rt) > UINT32_MAX) {
    throw jsi::JSError(rt, "mac_hmac_sha256: msg too large");
  }
  std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
  hmac_sha256(key.data(rt), static_cast<uint32_t>(key.size(rt)),
              msg.data(rt), static_cast<uint32_t>(msg.size(rt)),
              out.data());
  return wrapDigest(rt, std::move(out));
}

jsi::Value invoke_hmac_sha512(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto key = requireArrayBufferAt(rt, "mac_hmac_sha512", "key", args, count, 0);
  auto msg = requireArrayBufferAt(rt, "mac_hmac_sha512", "msg", args, count, 1);
  if (key.size(rt) > UINT32_MAX) {
    throw jsi::JSError(rt, "mac_hmac_sha512: key too large");
  }
  if (msg.size(rt) > UINT32_MAX) {
    throw jsi::JSError(rt, "mac_hmac_sha512: msg too large");
  }
  std::vector<uint8_t> out(SHA512_DIGEST_LENGTH);
  hmac_sha512(key.data(rt), static_cast<uint32_t>(key.size(rt)),
              msg.data(rt), static_cast<uint32_t>(msg.size(rt)),
              out.data());
  return wrapDigest(rt, std::move(out));
}

} // namespace

void registerMacMethods(MethodMap& map) {
  map.push_back({"mac_hmac_sha256", 2, invoke_hmac_sha256});
  map.push_back({"mac_hmac_sha512", 2, invoke_hmac_sha512});
}

}

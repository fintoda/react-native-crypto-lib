#pragma once

#include <ReactNativeCryptoLibSpecJSI.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace facebook::react::cryptolib {

// Signature of a JSI method thunk, matching TurboModule::MethodMetadata
// but defined here so domain modules don't need access to TurboModule's
// protected inner class. Impl.cpp repackages these into MethodMetadata
// entries on the real methodMap_.
using MethodFn =
  jsi::Value (*)(jsi::Runtime&, TurboModule&, const jsi::Value*, size_t);

struct MethodEntry {
  const char* name;
  size_t argCount;
  MethodFn fn;
};

using MethodMap = std::vector<MethodEntry>;

// Owns an std::vector<uint8_t> behind a jsi::MutableBuffer so native code
// can hand ArrayBuffers back to JS without copying.
class VectorBuffer : public jsi::MutableBuffer {
public:
  explicit VectorBuffer(std::vector<uint8_t>&& data)
    : data_(std::move(data)) {}
  size_t size() const override { return data_.size(); }
  uint8_t* data() override { return data_.data(); }

private:
  std::vector<uint8_t> data_;
};

// Returns a non-NULL pointer for ArrayBuffer data, even when size is 0.
// Some trezor-crypto functions (ripemd160, blake2b, etc.) assert(p != NULL)
// even when length is 0. JSI's ArrayBuffer::data() may return NULL for
// zero-length buffers on some platforms.
inline const uint8_t* safeData(jsi::Runtime& rt, const jsi::ArrayBuffer& buf) {
  static const uint8_t kEmpty = 0;
  return buf.size(rt) == 0 ? &kEmpty : buf.data(rt);
}

inline jsi::Value wrapDigest(jsi::Runtime& rt, std::vector<uint8_t>&& digest) {
  return jsi::ArrayBuffer(rt, std::make_shared<VectorBuffer>(std::move(digest)));
}

inline jsi::ArrayBuffer requireArrayBuffer(
  jsi::Runtime& rt,
  const char* methodName,
  const jsi::Value* args,
  size_t count
) {
  if (count < 1 || !args[0].isObject()) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": expected ArrayBuffer argument");
  }
  auto obj = args[0].asObject(rt);
  if (!obj.isArrayBuffer(rt)) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": argument must be an ArrayBuffer");
  }
  return obj.getArrayBuffer(rt);
}

inline jsi::ArrayBuffer requireArrayBufferAt(
  jsi::Runtime& rt,
  const char* methodName,
  const char* argName,
  const jsi::Value* args,
  size_t count,
  size_t index
) {
  if (count <= index || !args[index].isObject()) {
    throw jsi::JSError(
      rt,
      std::string(methodName) + ": " + argName + " must be an ArrayBuffer");
  }
  auto obj = args[index].asObject(rt);
  if (!obj.isArrayBuffer(rt)) {
    throw jsi::JSError(
      rt,
      std::string(methodName) + ": " + argName + " must be an ArrayBuffer");
  }
  return obj.getArrayBuffer(rt);
}

inline double requireIntAt(
  jsi::Runtime& rt,
  const char* methodName,
  const char* argName,
  const jsi::Value* args,
  size_t count,
  size_t index,
  double minValue,
  double maxValue
) {
  if (count <= index || !args[index].isNumber()) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": " + argName + " must be a number");
  }
  double v = args[index].asNumber();
  if (v < minValue || v > maxValue ||
      v != static_cast<double>(static_cast<int64_t>(v))) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": " + argName + " out of range");
  }
  return v;
}

inline bool requireBoolAt(
  jsi::Runtime& rt,
  const char* methodName,
  const char* argName,
  const jsi::Value* args,
  size_t count,
  size_t index
) {
  if (count <= index || !args[index].isBool()) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": " + argName + " must be a boolean");
  }
  return args[index].getBool();
}

inline std::string requireStringAt(
  jsi::Runtime& rt,
  const char* methodName,
  const char* argName,
  const jsi::Value* args,
  size_t count,
  size_t index
) {
  if (count <= index || !args[index].isString()) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": " + argName + " must be a string");
  }
  return args[index].getString(rt).utf8(rt);
}

// Each domain module (Hash, Mac, Kdf, Rng, Ecdsa, Schnorr) exposes one of
// these from its .cpp. The main Impl constructor calls them all so it can
// stay a thin orchestration layer.
void registerHashMethods(MethodMap& map);
void registerMacMethods(MethodMap& map);
void registerKdfMethods(MethodMap& map);
void registerRngMethods(MethodMap& map);
void registerEcdsaMethods(MethodMap& map);
void registerSchnorrMethods(MethodMap& map);
void registerEd25519Methods(MethodMap& map);
void registerEccMethods(MethodMap& map);
void registerAesMethods(MethodMap& map);
void registerBip39Methods(MethodMap& map);
void registerBip32Methods(MethodMap& map);

}

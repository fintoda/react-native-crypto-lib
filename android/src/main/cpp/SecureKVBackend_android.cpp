#include <fbjni/fbjni.h>

#include "../../../../cpp/SecureKVBackend.h"

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// Android backend for secureKV. Forwards to SecureKVBridge.kt over JNI;
// the Kotlin side wraps AndroidKeystore (AES-256-GCM master key) and writes
// blobs to <filesDir>/secure_kv/. fbjni handles JNIEnv attachment and
// translates Java exceptions into facebook::jni::JniException, which we
// remap to std::runtime_error so the JSI thunk layer (cpp/SecureKV.cpp)
// can wrap it the same way as iOS errors.

namespace facebook::react::cryptolib {

namespace jni = facebook::jni;
namespace {

constexpr const char* kBridge =
  "com/fintoda/reactnativecryptolib/SecureKVBridge";

// JniException::what() looks like
//   "com.fintoda.reactnativecryptolib.SecureKVUnavailableException: unavailable: ..."
//   "com.fintoda.reactnativecryptolib.SecureKVBiometricException: secureKV.set: user canceled: ..."
// We strip the FQCN prefix so the JS wrapper sees a clean "reason" string
// it can split on a single ': '. SecureKVUnavailableException keeps the
// "unavailable: " prefix so errors.ts can upgrade to SecureKVUnavailableError.
[[noreturn]] void rethrow(const jni::JniException& e) {
  std::string what = e.what();
  bool unavailable =
    what.find("SecureKVUnavailableException") != std::string::npos;
  bool biometric =
    what.find("SecureKVBiometricException") != std::string::npos;

  if (unavailable) {
    size_t cut = what.find("unavailable");
    if (cut != std::string::npos) {
      throw std::runtime_error(what.substr(cut));
    }
    throw std::runtime_error("unavailable");
  }
  if (biometric) {
    // Strip "com.fintoda...SecureKVBiometricException: " — the Kotlin
    // message is already self-explanatory ("user canceled: ...").
    size_t colonSpace = what.find(": ");
    if (colonSpace != std::string::npos) {
      throw std::runtime_error(what.substr(colonSpace + 2));
    }
    throw std::runtime_error(what);
  }
  throw std::runtime_error(what);
}

}  // namespace

void SecureKVBackend::set(
  const std::string& key, const uint8_t* data, size_t len, AccessControl ac
) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method =
      cls->getStaticMethod<void(jstring, jbyteArray, jint)>("set");
    auto keyJ = jni::make_jstring(key);
    auto valueJ = jni::JArrayByte::newArray(len);
    if (len > 0) {
      valueJ->setRegion(0, len, reinterpret_cast<const jbyte*>(data));
    }
    method(cls, keyJ.get(), valueJ.get(), static_cast<jint>(ac));
  } catch (const jni::JniException& e) {
    rethrow(e);
  }
}

std::optional<std::vector<uint8_t>> SecureKVBackend::get(
  const std::string& key
) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<jbyteArray(jstring)>("get");
    auto keyJ = jni::make_jstring(key);
    auto arr = method(cls, keyJ.get());
    if (arr == nullptr) return std::nullopt;
    size_t n = arr->size();
    std::vector<uint8_t> out(n);
    if (n > 0) {
      arr->getRegion(0, n, reinterpret_cast<jbyte*>(out.data()));
    }
    return out;
  } catch (const jni::JniException& e) {
    rethrow(e);
  }
}

bool SecureKVBackend::has(const std::string& key) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<jboolean(jstring)>("has");
    auto keyJ = jni::make_jstring(key);
    return method(cls, keyJ.get()) != JNI_FALSE;
  } catch (const jni::JniException& e) {
    rethrow(e);
  }
}

void SecureKVBackend::remove(const std::string& key) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<void(jstring)>("delete");
    auto keyJ = jni::make_jstring(key);
    method(cls, keyJ.get());
  } catch (const jni::JniException& e) {
    rethrow(e);
  }
}

std::vector<std::string> SecureKVBackend::list() {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<jstring()>("listJoined");
    auto joined = method(cls);
    if (joined == nullptr) return {};
    std::string s = joined->toStdString();
    std::vector<std::string> out;
    if (s.empty()) return out;
    size_t pos = 0;
    while (pos <= s.size()) {
      size_t nl = s.find('\n', pos);
      if (nl == std::string::npos) {
        out.emplace_back(s.substr(pos));
        break;
      }
      out.emplace_back(s.substr(pos, nl - pos));
      pos = nl + 1;
    }
    return out;
  } catch (const jni::JniException& e) {
    rethrow(e);
  }
}

void SecureKVBackend::clear() {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<void()>("clear");
    method(cls);
  } catch (const jni::JniException& e) {
    rethrow(e);
  }
}

bool SecureKVBackend::isHardwareBacked() {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<jboolean()>("isHardwareBacked");
    return method(cls) != JNI_FALSE;
  } catch (const jni::JniException& e) {
    rethrow(e);
  }
}

}  // namespace facebook::react::cryptolib

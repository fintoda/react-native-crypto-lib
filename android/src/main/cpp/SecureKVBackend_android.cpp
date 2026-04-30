#include <fbjni/fbjni.h>

#include "../../../../cpp/SecureKVBackend.h"
#include "JniRethrow.h"

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// Android backend for secureKV. Forwards to SecureKVBridge.kt over JNI;
// the Kotlin side wraps AndroidKeystore (AES-256-GCM master key) and writes
// blobs to <filesDir>/secure_kv/. fbjni handles JNIEnv attachment and
// translates Java exceptions into facebook::jni::JniException, which we
// remap to std::runtime_error via JniRethrow.h so the JSI thunk layer
// (cpp/SecureKV.cpp) can wrap it the same way as iOS errors.

namespace facebook::react::cryptolib {

namespace jni = facebook::jni;
namespace {

constexpr const char* kBridge =
  "com/fintoda/reactnativecryptolib/SecureKVBridge";

}  // namespace

void SecureKVBackend::set(
  const std::string& key,
  const uint8_t* data,
  size_t len,
  AccessControl ac,
  uint32_t validityWindowSec,
  const BiometricPromptCopy& prompt
) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<
      void(jstring, jbyteArray, jint, jint, jstring, jstring, jstring)
    >("set");
    auto keyJ = jni::make_jstring(key);
    auto valueJ = jni::JArrayByte::newArray(len);
    if (len > 0) {
      valueJ->setRegion(0, len, reinterpret_cast<const jbyte*>(data));
    }
    method(
      cls, keyJ.get(), valueJ.get(),
      static_cast<jint>(ac),
      static_cast<jint>(validityWindowSec),
      jni::make_jstring(prompt.title).get(),
      jni::make_jstring(prompt.subtitle).get(),
      jni::make_jstring(prompt.cancelLabel).get()
    );
  } catch (const jni::JniException& e) {
    rethrowJniException(e);
  }
}

std::optional<std::vector<uint8_t>> SecureKVBackend::get(
  const std::string& key,
  const BiometricPromptCopy& prompt
) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<
      jbyteArray(jstring, jstring, jstring, jstring)
    >("get");
    auto keyJ = jni::make_jstring(key);
    auto arr = method(
      cls, keyJ.get(),
      jni::make_jstring(prompt.title).get(),
      jni::make_jstring(prompt.subtitle).get(),
      jni::make_jstring(prompt.cancelLabel).get()
    );
    if (arr == nullptr) return std::nullopt;
    size_t n = arr->size();
    std::vector<uint8_t> out(n);
    if (n > 0) {
      arr->getRegion(0, n, reinterpret_cast<jbyte*>(out.data()));
    }
    return out;
  } catch (const jni::JniException& e) {
    rethrowJniException(e);
  }
}

bool SecureKVBackend::has(const std::string& key) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<jboolean(jstring)>("has");
    auto keyJ = jni::make_jstring(key);
    return method(cls, keyJ.get()) != JNI_FALSE;
  } catch (const jni::JniException& e) {
    rethrowJniException(e);
  }
}

void SecureKVBackend::remove(const std::string& key) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<void(jstring)>("delete");
    auto keyJ = jni::make_jstring(key);
    method(cls, keyJ.get());
  } catch (const jni::JniException& e) {
    rethrowJniException(e);
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
    rethrowJniException(e);
  }
}

void SecureKVBackend::clear() {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<void()>("clear");
    method(cls);
  } catch (const jni::JniException& e) {
    rethrowJniException(e);
  }
}

bool SecureKVBackend::isHardwareBacked() {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<jboolean()>("isHardwareBacked");
    return method(cls) != JNI_FALSE;
  } catch (const jni::JniException& e) {
    rethrowJniException(e);
  }
}

void SecureKVBackend::invalidateSession(const std::string& /*alias*/) {
  // No-op on Android: the biometric validity window is enforced by
  // AndroidKeystore at the OS layer and cannot be cleared from
  // userland. Callers either wait for the window to expire or store
  // the item with `validityWindow: 0` for per-call prompts. The
  // method exists so cross-platform code can call it without a
  // Platform.OS check.
}

BiometricStatus SecureKVBackend::biometricStatus() {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<jint()>("biometricStatusCode");
    jint code = method(cls);
    switch (code) {
      case 0: return BiometricStatus::Available;
      case 1: return BiometricStatus::NoHardware;
      case 2: return BiometricStatus::NotEnrolled;
      case 3: return BiometricStatus::HardwareUnavailable;
      case 4: return BiometricStatus::SecurityUpdateRequired;
      case 5: return BiometricStatus::UnsupportedOs;
      default: return BiometricStatus::HardwareUnavailable;
    }
  } catch (const jni::JniException& e) {
    rethrowJniException(e);
  }
}

}  // namespace facebook::react::cryptolib

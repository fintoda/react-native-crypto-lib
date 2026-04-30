#pragma once

#include <fbjni/fbjni.h>

#include <stdexcept>
#include <string>

// Shared JNI → std::runtime_error remapping used by both
// SecureKVBackend_android.cpp and BiometricBackend_android.cpp. Inspects
// the thrown Java exception's class name (FQCN) directly rather than
// substring-matching JniException::what(): the latter is fragile across
// fbjni versions and stack-trace formats.

namespace facebook::react::cryptolib {

namespace jni = facebook::jni;

namespace jni_rethrow_detail {

constexpr const char* kFqcnUnavailable =
  "com.fintoda.reactnativecryptolib.SecureKVUnavailableException";
constexpr const char* kFqcnBiometric =
  "com.fintoda.reactnativecryptolib.SecureKVBiometricException";

inline std::string javaClassName(jni::alias_ref<jni::JClass> cls) {
  // java.lang.Class.getName() returns the canonical FQCN with dots
  // (e.g. "java.lang.RuntimeException"). Use reflection here because
  // fbjni's JClass has no getName() helper.
  auto classOfClass = jni::findClassStatic("java/lang/Class");
  auto getName = classOfClass->getMethod<jni::local_ref<jni::JString>()>("getName");
  auto nameJ = getName(cls.get());
  return nameJ ? nameJ->toStdString() : std::string();
}

}  // namespace jni_rethrow_detail

// Maps SecureKV*Exception classes to clean std::runtime_error reasons.
// Keeps the "unavailable" prefix on SecureKVUnavailableException so the
// JS-side errors.ts upgrade to SecureKVUnavailableError still works.
[[noreturn]] inline void rethrowJniException(const jni::JniException& e) {
  using namespace jni_rethrow_detail;
  auto java = e.getThrowable();
  std::string fqcn = javaClassName(java->getClass());
  auto msgJ = java->getMessage();
  std::string msg = msgJ ? msgJ->toStdString() : std::string();

  if (fqcn == kFqcnUnavailable) {
    throw std::runtime_error(msg.empty() ? "unavailable" : msg);
  }
  if (fqcn == kFqcnBiometric) {
    // Kotlin already prefixes with the op-level context
    // (e.g. "secureKV.set: user canceled: ..."); pass through verbatim.
    throw std::runtime_error(msg.empty() ? "biometric failed" : msg);
  }
  // Unknown Java exception — surface FQCN + message so callers see
  // something more diagnosable than a bare what() string.
  if (fqcn.empty()) {
    throw std::runtime_error(msg.empty() ? "unknown JNI exception" : msg);
  }
  throw std::runtime_error(msg.empty() ? fqcn : fqcn + ": " + msg);
}

}  // namespace facebook::react::cryptolib

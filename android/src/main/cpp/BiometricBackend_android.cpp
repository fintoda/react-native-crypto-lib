#include <fbjni/fbjni.h>

#include "../../../../cpp/BiometricBackend.h"

#include <stdexcept>
#include <string>

// Android implementation of BiometricBackend. Delegates to
// SecureKVBridge.biometricAuthenticate(), which reuses the same
// CryptoObject-less BiometricPrompt path that secureKV's windowed
// keys go through. The bridge handles FragmentActivity lookup and
// blocks on a CountDownLatch until the prompt resolves.

namespace facebook::react::cryptolib {

namespace jni = facebook::jni;
namespace {

constexpr const char* kBridge =
  "com/fintoda/reactnativecryptolib/SecureKVBridge";

// JniException::what() looks like
//   "com.fintoda.reactnativecryptolib.SecureKVBiometricException: biometric.authenticate: user canceled: ..."
// Strip the FQCN prefix so the JS wrapper sees a clean message it can
// split on a single ': '. Mirrors the secureKV rethrow logic.
[[noreturn]] void rethrow(const jni::JniException& e) {
  std::string what = e.what();
  bool biometric =
    what.find("SecureKVBiometricException") != std::string::npos;
  if (biometric) {
    size_t colonSpace = what.find(": ");
    if (colonSpace != std::string::npos) {
      throw std::runtime_error(what.substr(colonSpace + 2));
    }
  }
  throw std::runtime_error(what);
}

}  // namespace

void BiometricBackend::authenticate(
  const std::string& title,
  const std::string& subtitle,
  const std::string& cancelLabel
) {
  try {
    auto cls = jni::findClassStatic(kBridge);
    auto method = cls->getStaticMethod<
      void(jstring, jstring, jstring)
    >("biometricAuthenticate");
    method(
      cls,
      jni::make_jstring(title).get(),
      jni::make_jstring(subtitle).get(),
      jni::make_jstring(cancelLabel).get()
    );
  } catch (const jni::JniException& e) {
    rethrow(e);
  }
}

}  // namespace facebook::react::cryptolib

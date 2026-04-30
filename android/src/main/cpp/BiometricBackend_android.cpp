#include <fbjni/fbjni.h>

#include "../../../../cpp/BiometricBackend.h"
#include "JniRethrow.h"

#include <stdexcept>
#include <string>

// Android implementation of BiometricBackend. Delegates to
// SecureKVBridge.biometricAuthenticate(), which reuses the same
// CryptoObject-less BiometricPrompt path that secureKV's windowed
// keys go through. The bridge handles FragmentActivity lookup and
// blocks on a CountDownLatch until the prompt resolves.
//
// JNI exception remapping is shared with SecureKVBackend_android via
// JniRethrow.h so both surfaces classify SecureKVBiometricException /
// SecureKVUnavailableException identically.

namespace facebook::react::cryptolib {

namespace jni = facebook::jni;
namespace {

constexpr const char* kBridge =
  "com/fintoda/reactnativecryptolib/SecureKVBridge";

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
    rethrowJniException(e);
  }
}

}  // namespace facebook::react::cryptolib

#include <fbjni/fbjni.h>

#include "../../../../cpp/BiometricBackend.h"
#include "JniRethrow.h"

#include <exception>
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
//
// Same WithClassLoader requirement as SecureKVBackend_android: the bg
// worker (detached std::thread spawned by makePromiseAsync) needs the
// app classloader to resolve `SecureKVBridge`, so we wrap the body in
// `ThreadScope::WithClassLoader`.

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
  std::exception_ptr err;
  jni::ThreadScope::WithClassLoader([&]() {
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
      try { rethrowJniException(e); }
      catch (...) { err = std::current_exception(); }
    } catch (...) {
      err = std::current_exception();
    }
  });
  if (err) std::rethrow_exception(err);
}

}  // namespace facebook::react::cryptolib

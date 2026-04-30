#include <fbjni/fbjni.h>

#include "../../../../cpp/SecureKVBackend.h"
#include "JniRethrow.h"

#include <cstring>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

// Android backend for secureKV. Forwards to SecureKVBridge.kt over JNI;
// the Kotlin side wraps AndroidKeystore (AES-256-GCM master key) and writes
// blobs to <filesDir>/secure_kv/. fbjni handles JNIEnv attachment and
// translates Java exceptions into facebook::jni::JniException, which we
// remap to std::runtime_error via JniRethrow.h so the JSI thunk layer
// (cpp/SecureKV.cpp) can wrap it the same way as iOS errors.
//
// Every method runs on a worker thread spawned by makePromiseAsync (a
// detached std::thread). Without `ThreadScope::WithClassLoader` such
// threads attach with the bootstrap classloader only and cannot resolve
// our Kotlin classes (`findClassStatic` would throw ClassNotFoundException
// or fbjni would surface "Unable to retrieve JNIEnv*" depending on the
// failure mode). The `inJniScope` helper attaches the thread + sets the
// app classloader for the lifetime of the closure, then restores both
// on exit. On the JS thread (already attached, classloader already set)
// it's still safe — fbjni skips the redundant attach.

namespace facebook::react::cryptolib {

namespace jni = facebook::jni;
namespace {

constexpr const char* kBridge =
  "com/fintoda/reactnativecryptolib/SecureKVBridge";

// Runs `fn` inside a `ThreadScope::WithClassLoader` block so the bg
// worker can resolve app classes. Propagates exceptions from the
// closure out of the scope cleanly. Returns the closure's return value
// (or void) — wrapped through std::optional<R> for value-returning
// closures so we don't constrain R to be default-constructible.
template <typename F>
auto inJniScope(F&& fn) -> decltype(fn()) {
  using R = decltype(fn());
  std::exception_ptr err;
  if constexpr (std::is_void_v<R>) {
    jni::ThreadScope::WithClassLoader([&]() {
      try { fn(); }
      catch (...) { err = std::current_exception(); }
    });
    if (err) std::rethrow_exception(err);
  } else {
    std::optional<R> result;
    jni::ThreadScope::WithClassLoader([&]() {
      try { result.emplace(fn()); }
      catch (...) { err = std::current_exception(); }
    });
    if (err) std::rethrow_exception(err);
    return std::move(*result);
  }
}

}  // namespace

void SecureKVBackend::set(
  const std::string& key,
  const uint8_t* data,
  size_t len,
  AccessControl ac,
  uint32_t validityWindowSec,
  uint8_t slotKind,
  const BiometricPromptCopy& prompt
) {
  inJniScope([&]() {
    try {
      auto cls = jni::findClassStatic(kBridge);
      auto method = cls->getStaticMethod<
        void(jstring, jbyteArray, jint, jint, jint, jstring, jstring, jstring)
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
        static_cast<jint>(slotKind),
        jni::make_jstring(prompt.title).get(),
        jni::make_jstring(prompt.subtitle).get(),
        jni::make_jstring(prompt.cancelLabel).get()
      );
    } catch (const jni::JniException& e) {
      rethrowJniException(e);
    }
  });
}

std::optional<std::vector<uint8_t>> SecureKVBackend::get(
  const std::string& key,
  const BiometricPromptCopy& prompt
) {
  return inJniScope([&]() -> std::optional<std::vector<uint8_t>> {
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
  });
}

bool SecureKVBackend::has(const std::string& key) {
  return inJniScope([&]() -> bool {
    try {
      auto cls = jni::findClassStatic(kBridge);
      auto method = cls->getStaticMethod<jboolean(jstring)>("has");
      auto keyJ = jni::make_jstring(key);
      return method(cls, keyJ.get()) != JNI_FALSE;
    } catch (const jni::JniException& e) {
      rethrowJniException(e);
    }
  });
}

void SecureKVBackend::remove(const std::string& key) {
  inJniScope([&]() {
    try {
      auto cls = jni::findClassStatic(kBridge);
      auto method = cls->getStaticMethod<void(jstring)>("delete");
      auto keyJ = jni::make_jstring(key);
      method(cls, keyJ.get());
    } catch (const jni::JniException& e) {
      rethrowJniException(e);
    }
  });
}

std::vector<std::string> SecureKVBackend::list() {
  return inJniScope([&]() -> std::vector<std::string> {
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
  });
}

void SecureKVBackend::clear() {
  inJniScope([&]() {
    try {
      auto cls = jni::findClassStatic(kBridge);
      auto method = cls->getStaticMethod<void()>("clear");
      method(cls);
    } catch (const jni::JniException& e) {
      rethrowJniException(e);
    }
  });
}

bool SecureKVBackend::isHardwareBacked() {
  return inJniScope([&]() -> bool {
    try {
      auto cls = jni::findClassStatic(kBridge);
      auto method = cls->getStaticMethod<jboolean()>("isHardwareBacked");
      return method(cls) != JNI_FALSE;
    } catch (const jni::JniException& e) {
      rethrowJniException(e);
    }
  });
}

BackendItemMetadata SecureKVBackend::metadata(const std::string& key) {
  return inJniScope([&]() -> BackendItemMetadata {
    try {
      auto cls = jni::findClassStatic(kBridge);
      // Kotlin returns int[5] = [exists 0/1, accessControl 0/1,
      // validityWindow, hasPassphrase 0/1, slotKind]. Returning null for
      // missing items would be ambiguous with errors; using a length-5
      // array with `exists=0` instead is unambiguous.
      auto method = cls->getStaticMethod<jintArray(jstring)>("metadata");
      auto keyJ = jni::make_jstring(key);
      auto arr = method(cls, keyJ.get());
      BackendItemMetadata out;
      if (arr == nullptr || arr->size() < 5) return out;
      jint buf[5];
      arr->getRegion(0, 5, buf);
      out.exists = buf[0] != 0;
      if (!out.exists) return out;
      out.accessControl = static_cast<AccessControl>(buf[1] & 0xff);
      out.validityWindowSec = static_cast<uint32_t>(buf[2]);
      out.hasPassphrase = buf[3] != 0;
      out.slotKind = static_cast<uint8_t>(buf[4] & 0xff);
      return out;
    } catch (const jni::JniException& e) {
      rethrowJniException(e);
    }
  });
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
  return inJniScope([&]() -> BiometricStatus {
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
  });
}

}  // namespace facebook::react::cryptolib

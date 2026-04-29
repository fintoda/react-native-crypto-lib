#include "BiometricBackend.h"
#include "Common.h"
#include "SecureKVBackend.h"

#include <stdexcept>
#include <string>

namespace facebook::react::cryptolib {
namespace {

[[noreturn]] void wrap(jsi::Runtime& rt, const char* op, const std::exception& e) {
  throw jsi::JSError(rt, std::string(op) + ": " + e.what());
}

// Mirrors the BiometricStatus enum values used by JS. Kept identical
// to the secureKV side so callers see one stable string set.
const char* biometricStatusName(BiometricStatus s) {
  switch (s) {
    case BiometricStatus::Available: return "available";
    case BiometricStatus::NoHardware: return "no_hardware";
    case BiometricStatus::NotEnrolled: return "not_enrolled";
    case BiometricStatus::HardwareUnavailable: return "hardware_unavailable";
    case BiometricStatus::SecurityUpdateRequired: return "security_update_required";
    case BiometricStatus::UnsupportedOs: return "unsupported_os";
  }
  return "hardware_unavailable";
}

jsi::Value invoke_biometric_status(
  jsi::Runtime& rt, TurboModule&, const jsi::Value*, size_t
) {
  return makePromise(rt, [](jsi::Runtime& rt) -> jsi::Value {
    try {
      auto s = SecureKVBackend::biometricStatus();
      return jsi::String::createFromUtf8(rt, biometricStatusName(s));
    } catch (const std::exception& e) {
      wrap(rt, "biometric_status", e);
    }
  });
}

jsi::Value invoke_biometric_authenticate(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  auto title =
    requireStringAt(rt, "biometric_authenticate", "title", args, count, 0);
  auto subtitle =
    requireStringAt(rt, "biometric_authenticate", "subtitle", args, count, 1);
  auto cancelLabel = requireStringAt(
    rt, "biometric_authenticate", "cancelLabel", args, count, 2);
  return makePromise(
    rt,
    [t = std::move(title), s = std::move(subtitle), c = std::move(cancelLabel)](
      jsi::Runtime& rt
    ) -> jsi::Value {
      try {
        BiometricBackend::authenticate(t, s, c);
        return jsi::Value::undefined();
      } catch (const std::exception& e) {
        wrap(rt, "biometric_authenticate", e);
      }
    }
  );
}

}  // namespace

void registerBiometricMethods(MethodMap& map) {
  map.push_back({"biometric_status",       0, invoke_biometric_status});
  map.push_back({"biometric_authenticate", 3, invoke_biometric_authenticate});
}

}  // namespace facebook::react::cryptolib

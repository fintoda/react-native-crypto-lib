#include "BiometricBackend.h"
#include "Common.h"
#include "SecureKVBackend.h"

#include <stdexcept>
#include <string>

namespace facebook::react::cryptolib {
namespace {

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
  return safeAsyncThunk(rt, [&] {
    return makePromiseAsync<BiometricStatus>(
      rt, "biometric_status",
      []() -> BiometricStatus {
        return SecureKVBackend::biometricStatus();
      },
      [](jsi::Runtime& rt, BiometricStatus&& s) -> jsi::Value {
        return jsi::String::createFromUtf8(rt, biometricStatusName(s));
      }
    );
  });
}

jsi::Value invoke_biometric_authenticate(
  jsi::Runtime& rt, TurboModule&, const jsi::Value* args, size_t count
) {
  return safeAsyncThunk(rt, [&] {
    // Validate prompt copy on the JS thread; the actual blocking prompt
    // runs on a worker via makePromiseAsync so JS-thread animations and
    // timers stay responsive while the user is presented with Face ID /
    // fingerprint.
    std::string title =
      requireStringAt(rt, "biometric_authenticate", "title", args, count, 0);
    std::string subtitle =
      requireStringAt(rt, "biometric_authenticate", "subtitle", args, count, 1);
    std::string cancelLabel = requireStringAt(
      rt, "biometric_authenticate", "cancelLabel", args, count, 2);

    return makePromiseAsync<bool>(
      rt, "biometric_authenticate",
      [title = std::move(title), subtitle = std::move(subtitle),
       cancelLabel = std::move(cancelLabel)]() -> bool {
        BiometricBackend::authenticate(title, subtitle, cancelLabel);
        return true;
      },
      [](jsi::Runtime&, bool&&) -> jsi::Value {
        return jsi::Value::undefined();
      }
    );
  });
}

}  // namespace

void registerBiometricMethods(MethodMap& map) {
  map.push_back({"biometric_status",       0, invoke_biometric_status});
  map.push_back({"biometric_authenticate", 3, invoke_biometric_authenticate});
}

}  // namespace facebook::react::cryptolib

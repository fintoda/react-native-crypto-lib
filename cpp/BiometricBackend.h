#pragma once

#include <string>

namespace facebook::react::cryptolib {

// Native biometric prompt — UX gate, **not** a cryptographic gate.
//
// Use this for "soft" gating like hiding a balances screen behind a
// Face ID prompt. The prompt is not bound to any cryptographic
// operation, so a successful return is purely a statement about the
// system's biometric UI flow — a rooted attacker can in principle
// short-circuit it. For high-assurance gates use
// `secureKV.bip32.sign*` / `secureKV.raw.sign*`, where authentication
// is tied to a Keystore / Keychain operation.
//
// `BiometricBackend::status()` is intentionally absent — query
// availability via `SecureKVBackend::biometricStatus()`; the
// underlying check (LAContext.canEvaluatePolicy on iOS,
// BiometricManager.canAuthenticate on Android) is identical.
class BiometricBackend {
 public:
  // Shows a system biometric prompt and blocks the calling thread
  // until the user authenticates, cancels, or the system errors.
  //
  // Label semantics:
  //   iOS    : `subtitle` (falling back to `title` if empty) maps to
  //            `LAContext.localizedReason`; `cancelLabel` to
  //            `LAContext.localizedCancelTitle`. iOS has no separate
  //            title slot — the system always shows the app name.
  //   Android: the three labels map to `BiometricPrompt.PromptInfo`'s
  //            `setTitle` / `setSubtitle` / `setNegativeButtonText`.
  //
  // On success, returns. On user cancel or system failure, throws
  // std::runtime_error with a message starting with
  //   "user canceled: ..." for user-driven dismissals, or
  //   "biometric failed: ..." for hard failures (lockout, no enrolled
  //   biometric, hardware unavailable, etc.)
  // so the JS wrapper can distinguish UX dismissals from real
  // unavailability.
  static void authenticate(
    const std::string& title,
    const std::string& subtitle,
    const std::string& cancelLabel
  );
};

}  // namespace facebook::react::cryptolib

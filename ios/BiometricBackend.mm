#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#include "../cpp/BiometricBackend.h"

#include <stdexcept>
#include <string>

// iOS implementation of BiometricBackend. Wraps LAContext.evaluatePolicy
// against `LAPolicyDeviceOwnerAuthenticationWithBiometrics` — strictly
// biometric, no passcode fallback. The fallback button is hidden by
// setting `localizedFallbackTitle = @""`.

namespace facebook::react::cryptolib {
namespace {

NSString* nsString(const std::string& s) {
  return [[NSString alloc] initWithBytes:s.data()
                                  length:s.size()
                                encoding:NSUTF8StringEncoding];
}

bool isCancelCode(NSInteger code) {
  switch (code) {
    case LAErrorUserCancel:
    case LAErrorAppCancel:
    case LAErrorSystemCancel:
      return true;
    default:
      return false;
  }
}

}  // namespace

void BiometricBackend::authenticate(
  const std::string& title,
  const std::string& subtitle,
  const std::string& cancelLabel
) {
  LAContext* ctx = [[LAContext alloc] init];

  // Always-fresh prompt — no implicit reuse window. Callers wanting
  // session-style auth should use `secureKV.bip32.*` with a
  // `validityWindow`, where reuse is gated by Keychain itself.
  ctx.touchIDAuthenticationAllowableReuseDuration = 0;

  // Empty fallback title hides the "Enter Passcode" button. We only
  // expose biometric in this API to match the Android BIOMETRIC_STRONG
  // contract used by `secureKV`.
  ctx.localizedFallbackTitle = @"";

  if (!cancelLabel.empty()) {
    ctx.localizedCancelTitle = nsString(cancelLabel);
  }

  NSError* probeErr = nil;
  if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                        error:&probeErr]) {
    NSString* desc = probeErr.localizedDescription
      ? probeErr.localizedDescription
      : @"biometric not available";
    throw std::runtime_error(
      std::string("biometric failed: ") + [desc UTF8String]);
  }

  // iOS surfaces a single user-visible string. Prefer subtitle, fall
  // back to title; if neither is set, use a neutral default so the
  // prompt never renders blank — iOS rejects the call if reason is
  // empty.
  std::string reason =
    !subtitle.empty() ? subtitle :
    !title.empty()    ? title :
                        std::string("Authenticate to continue");

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block BOOL success = NO;
  __block NSError* authErr = nil;

  [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
      localizedReason:nsString(reason)
                reply:^(BOOL ok, NSError* error) {
                  success = ok;
                  authErr = error;
                  dispatch_semaphore_signal(sema);
                }];

  dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

  if (success) return;

  if (authErr == nil) {
    throw std::runtime_error("biometric failed: unknown error");
  }

  NSString* desc = authErr.localizedDescription
    ? authErr.localizedDescription
    : @"unknown";
  std::string descUtf8 = [desc UTF8String];
  std::string codeStr = std::to_string((long)authErr.code);

  if (isCancelCode(authErr.code)) {
    throw std::runtime_error(
      "user canceled: " + descUtf8 + " (code " + codeStr + ")");
  }

  throw std::runtime_error(
    "biometric failed: " + descUtf8 + " (code " + codeStr + ")");
}

}  // namespace facebook::react::cryptolib

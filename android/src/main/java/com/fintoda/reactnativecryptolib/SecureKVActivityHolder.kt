package com.fintoda.reactnativecryptolib

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.module.annotations.ReactModule

/**
 * Eagerly-constructed companion to the (pure-cxx) TurboModule.
 *
 * Its sole purpose is to capture the host's [ReactApplicationContext] at
 * RN startup so that [SecureKVBridge] can later look up the current
 * Activity for [androidx.biometric.BiometricPrompt]. Marked
 * `needsEagerInit = true` in [ReactNativeCryptoLibPackage] so RN
 * constructs it during catalyst initialisation rather than waiting for
 * the first JS call.
 *
 * Exposes no JS-callable methods. JS code never touches this module
 * directly — `secureKV.*` goes through the C++ Turbo Module, which then
 * calls into [SecureKVBridge], which uses the bound RAC.
 */
@ReactModule(name = SecureKVActivityHolder.NAME, needsEagerInit = true)
class SecureKVActivityHolder(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {
  init {
    SecureKVBridge.bindReactContext(reactContext)
  }

  override fun getName(): String = NAME

  companion object {
    const val NAME: String = "SecureKVActivityHolder"
  }
}

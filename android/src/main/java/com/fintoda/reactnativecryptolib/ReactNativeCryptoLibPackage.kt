package com.fintoda.reactnativecryptolib

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

/**
 * ReactPackage for autolinking and biometric Activity plumbing.
 *
 * The actual TurboModule lives in C++ ([ReactNativeCryptoLibImpl]) and is
 * wired through `cxxModuleCMakeListsPath` in `react-native.config.js`.
 * This Java-side package serves two purposes:
 *
 * 1. It exists so React Native's autolinker stops classifying us as
 *    `isPureCxxDependency` and starts including the Android Gradle
 *    module — which in turn ships [SecureKVBridge] and the
 *    Keystore-backed AAR resources.
 * 2. It registers [SecureKVActivityHolder] as an eagerly-initialised
 *    Java module that captures `ReactApplicationContext` so the bridge
 *    can find the current Activity for `BiometricPrompt`.
 */
class ReactNativeCryptoLibPackage : BaseReactPackage() {
  override fun getModule(
    name: String,
    reactContext: ReactApplicationContext
  ): NativeModule? {
    return if (name == SecureKVActivityHolder.NAME) {
      SecureKVActivityHolder(reactContext)
    } else {
      null
    }
  }

  override fun getReactModuleInfoProvider(): ReactModuleInfoProvider =
    ReactModuleInfoProvider {
      mapOf(
        SecureKVActivityHolder.NAME to ReactModuleInfo(
          /* name */ SecureKVActivityHolder.NAME,
          /* className */ SecureKVActivityHolder::class.java.name,
          /* canOverrideExistingModule */ false,
          /* needsEagerInit */ true,
          /* isCxxModule */ false,
          /* isTurboModule */ false
        )
      )
    }
}

package com.fintoda.reactnativecryptolib

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfoProvider

/**
 * Empty ReactPackage for autolinking.
 *
 * The actual TurboModule lives in C++ ([ReactNativeCryptoLibImpl]) and is
 * wired through `cxxModuleCMakeListsPath` in `react-native.config.js`.
 * This Java-side package exists only so that React Native's autolinker
 * stops classifying us as `isPureCxxDependency` and starts including the
 * Android Gradle module — which in turn ships [SecureKVBridge] and the
 * Keystore-backed AAR resources.
 */
class ReactNativeCryptoLibPackage : BaseReactPackage() {
  override fun getModule(
    name: String,
    reactContext: ReactApplicationContext
  ): NativeModule? = null

  override fun getReactModuleInfoProvider(): ReactModuleInfoProvider =
    ReactModuleInfoProvider { emptyMap() }
}

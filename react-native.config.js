/**
 * @type {import('@react-native-community/cli-types').UserDependencyConfig}
 */
module.exports = {
  dependency: {
    platforms: {
      android: {
        cmakeListsPath: 'generated/jni/CMakeLists.txt',
        cxxModuleCMakeListsModuleName: 'fintoda-react-native-crypto-lib',
        cxxModuleCMakeListsPath: 'CMakeLists.txt',
        cxxModuleHeaderName: 'ReactNativeCryptoLibImpl',
        // The TurboModule itself is C++-only, but we ship a companion
        // Kotlin AAR (SecureKVBridge → AndroidKeystore). Declaring an
        // empty ReactPackage here flips autolinking's
        // `isPureCxxDependency` flag off so the Gradle module under
        // android/ gets included in host builds.
        packageImportPath:
          'import com.fintoda.reactnativecryptolib.ReactNativeCryptoLibPackage;',
        packageInstance: 'new ReactNativeCryptoLibPackage()',
      },
    },
  },
};

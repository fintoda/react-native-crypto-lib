#include "ReactNativeCryptoLibImpl.h"

#include "Common.h"

namespace facebook::react {

ReactNativeCryptoLibImpl::ReactNativeCryptoLibImpl(
  std::shared_ptr<CallInvoker> jsInvoker
)
  : NativeReactNativeCryptoLibCxxSpec(std::move(jsInvoker)) {
  // Each domain module (Hash, Mac, Kdf, Rng, Ecdsa, Schnorr) owns its own
  // JSI thunks and returns a flat list of (name, argCount, fn) entries.
  // We translate them into TurboModule::MethodMetadata here so the domain
  // files don't need access to TurboModule's protected inner type.
  cryptolib::MethodMap entries;
  entries.reserve(64);
  cryptolib::registerHashMethods(entries);
  cryptolib::registerMacMethods(entries);
  cryptolib::registerKdfMethods(entries);
  cryptolib::registerRngMethods(entries);
  cryptolib::registerEcdsaMethods(entries);
  cryptolib::registerSchnorrMethods(entries);
  cryptolib::registerEd25519Methods(entries);
  cryptolib::registerEccMethods(entries);
  cryptolib::registerAesMethods(entries);
  cryptolib::registerBip39Methods(entries);
  cryptolib::registerBip32Methods(entries);
  cryptolib::registerSlip39Methods(entries);
  cryptolib::registerSecureKVMethods(entries);
  cryptolib::registerSecureKVSignMethods(entries);
  cryptolib::registerBiometricMethods(entries);

  for (const auto& e : entries) {
    methodMap_[e.name] = MethodMetadata{e.argCount, e.fn};
  }
}

}

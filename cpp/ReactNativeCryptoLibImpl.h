#pragma once

#include <ReactNativeCryptoLibSpecJSI.h>

#include <memory>

namespace facebook::react {

class ReactNativeCryptoLibImpl
  : public NativeReactNativeCryptoLibCxxSpec<ReactNativeCryptoLibImpl> {
public:
  ReactNativeCryptoLibImpl(std::shared_ptr<CallInvoker> jsInvoker);
};

}

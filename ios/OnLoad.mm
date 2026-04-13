#import <Foundation/Foundation.h>
#import "ReactNativeCryptoLibImpl.h"
#import <ReactCommon/CxxTurboModuleUtils.h>

@interface ReactNativeCryptoLibOnLoad : NSObject
@end

@implementation ReactNativeCryptoLibOnLoad

using namespace facebook::react;

+ (void)load
{
  registerCxxModuleToGlobalModuleMap(
    std::string(ReactNativeCryptoLibImpl::kModuleName),
    [](std::shared_ptr<CallInvoker> jsInvoker) {
      return std::make_shared<ReactNativeCryptoLibImpl>(jsInvoker);
    }
  );
}

@end

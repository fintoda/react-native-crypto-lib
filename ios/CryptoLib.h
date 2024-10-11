#ifdef __cplusplus
#import "react-native-crypto-lib.h"
#endif

#ifdef RCT_NEW_ARCH_ENABLED
#import "RNCryptoLibSpec.h"

@interface CryptoLib : NSObject <NativeCryptoLibSpec>
#else
#import <React/RCTBridgeModule.h>

@interface CryptoLib : NSObject <RCTBridgeModule>
#endif

@end

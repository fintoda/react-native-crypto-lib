#import "CryptoLib.h"

#include <cstring>

#import "memzero.h"
#import "bip39.h"
#import "bip32.h"
#import "aes.h"
#import "zkp_bip340.h"
#import "zkp_context.h"

@implementation CryptoLib
RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(
  randomNumber:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject)
{
  NSNumber *result = @(cryptolib::randomNumber());
  resolve(result);
}

RCT_EXPORT_METHOD(randomBytes:(double)length 
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  uint8_t *bytes = (uint8_t *) malloc(length);
  cryptolib::randomBytes(bytes, length);

  NSData *result = [NSData dataWithBytes:bytes length:length];

  free(bytes);
  resolve([result base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  randomBytesSync:(double)length
) {
  uint8_t *bytes = (uint8_t *) malloc(length);
  cryptolib::randomBytes(bytes, length);

  NSData *result = [NSData dataWithBytes:bytes length:length];

  free(bytes);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hash:(double)algorithm
  data:(NSString *)data
) {
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];

  size_t hashSize = 0;
  uint8_t *hash;
  NSData *result;

  switch((HASH_TYPE) algorithm){
    case SHA1:
    case RIPEMD160:
    case HASH160:
      hashSize = 20;
      break;
    case SHA256:
    case SHA3_256:
    case KECCAK_256:
    case HASH256:
      hashSize = 32;
      break;
    case SHA512:
    case SHA3_512:
    case KECCAK_512:
      hashSize = 64;
      break;
    
    default:
      return nil;
  }

  hash = (uint8_t *) malloc(hashSize);
  cryptolib::hash((HASH_TYPE) algorithm, (uint8_t *)[raw_data bytes], [raw_data length], hash);
  
  result = [NSData dataWithBytes:hash length:hashSize];

  free(hash);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hmac:(double)algorithm
  key:(NSString *)key
  data:(NSString *)data
) {
  NSData *raw_key = [[NSData alloc]initWithBase64EncodedString:key options:0];
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];

  size_t hashSize = 0;
  uint8_t *hash;
  NSData *result;

  switch((HASH_TYPE) algorithm){
    case SHA256:
      hashSize = 32;
      break;
    case SHA512:
      hashSize = 64;
      break;
    
    default:
      return nil;
  }

  hash = (uint8_t *) malloc(hashSize);
  cryptolib::hmac(
    (HASH_TYPE) algorithm,
    (uint8_t *)[raw_key bytes],
    [raw_key length],
    (uint8_t *)[raw_data bytes],
    [raw_data length],
    hash
  );
  
  result = [NSData dataWithBytes:hash length:hashSize];

  free(hash);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_METHOD(
  pbkdf2:(double)algorithm
  pass:(NSString *)pass
  salt:(NSString *)salt
  iterations:(double)iterations
  keyLength:(double)keyLength
  resolve:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_pass = [[NSData alloc]initWithBase64EncodedString:pass options:0];
    NSData *raw_salt = [[NSData alloc]initWithBase64EncodedString:salt options:0];

    uint8_t *hash = (uint8_t *) malloc(keyLength);

    cryptolib::pbkdf2(
      (HASH_TYPE) algorithm,
      (uint8_t *)[raw_pass bytes], (uint32_t)[raw_pass length],
      (uint8_t *)[raw_salt bytes], (uint32_t)[raw_salt length],
      (uint32_t) iterations,
      hash, keyLength
    );

    NSData *result = [NSData dataWithBytes:hash length:keyLength];

    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_EXPORT_METHOD(mnemonicToSeed:(NSString *)mnemonic
  passphrase:(NSString *)passphrase
  resolve:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    uint8_t *seed = (uint8_t *) malloc(64);
    cryptolib::mnemonicToSeed([mnemonic UTF8String], [passphrase UTF8String], seed);
    NSData *result = [NSData dataWithBytes:seed length:64];
    free(seed);

    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_EXPORT_METHOD(
  generateMnemonic:(double)strength
  resolve:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  const char *mnemonic = cryptolib::generateMnemonic((uint32_t)strength);
  NSString *result = [NSString stringWithUTF8String:mnemonic];
  mnemonic_clear();
  resolve(result);
}

RCT_EXPORT_METHOD(
  validateMnemonic:(NSString *)mnemonic
  resolve:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  int result = cryptolib::validateMnemonic([mnemonic UTF8String]);
  resolve([NSNumber numberWithInt: result]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hdNodeFromSeed:(NSString *)curve
  seed:(NSString *)seed
) {
  NSData *raw_seed = [[NSData alloc]initWithBase64EncodedString:seed options:0];
  HDNode node = {0};

  int success = hdnode_from_seed((const uint8_t *)[raw_seed bytes], [raw_seed length], [curve UTF8String], &node);
  memzero((void *)[raw_seed bytes], [raw_seed length]);

  if (success != 1) {
    memzero(&node, sizeof(HDNode));
    @throw [NSException exceptionWithName:@"Error" reason:@"seed error" userInfo:nil];
  }

  uint32_t fp = hdnode_fingerprint(&node);

  NSDictionary *result = @{
    @"depth": [NSNumber numberWithUnsignedInt: node.depth],
    @"child_num": [NSNumber numberWithUnsignedInt: node.child_num],
    @"chain_code": [
      [NSData dataWithBytes: node.chain_code length: sizeof(node.chain_code)]
      base64EncodedStringWithOptions:0
    ],
    @"private_key": [
      [NSData dataWithBytes: node.private_key length: sizeof(node.private_key)]
      base64EncodedStringWithOptions:0
    ],
    @"public_key": [
      [NSData dataWithBytes: node.public_key length: sizeof(node.public_key)]
      base64EncodedStringWithOptions:0
    ],
    @"fingerprint": [NSNumber numberWithUnsignedInt: fp],
    @"curve": curve,
    @"private_derive": @true,
  };

  memzero(&node, sizeof(HDNode));
  fp = 0;

  return result;
}

#ifdef RCT_NEW_ARCH_ENABLED
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hdNodeDerive:(JS::NativeCryptoLib::HDNode &)data
  path:(NSArray<NSNumber *> *)path
) {
  HDNode node = {};
  
  node.depth = (uint32_t)data.depth();
  node.child_num = (uint32_t)data.child_num();
  
  NSString * chain_code_str = data.chain_code();
  NSString * private_key_str = data.private_key();
  NSString * public_key_str = data.public_key();
  
  NSData *chain_code;
  NSData *private_key;
  NSData *public_key;
  
  if (chain_code_str) {
    chain_code = [[NSData alloc] initWithBase64EncodedString:data.chain_code() options:0];
    if ([chain_code length] == sizeof(node.chain_code)) {
      memcpy(&node.chain_code, [chain_code bytes], sizeof(node.chain_code));
    }
  }
  if (private_key_str) {
    NSData *private_key = [[NSData alloc] initWithBase64EncodedString:data.private_key() options:0];
    if ([private_key length] == sizeof(node.private_key)) {
      memcpy(&node.private_key, [private_key bytes], sizeof(node.private_key));
    }
  }
  if (public_key_str) {
    NSData *public_key = [[NSData alloc] initWithBase64EncodedString:data.public_key() options:0];
    if ([public_key length] == sizeof(node.public_key)) {
      memcpy(&node.public_key, [public_key bytes], sizeof(node.public_key));
    }
  }

  NSString *curve = data.curve();
  
  if (curve) {
    node.curve = get_curve_by_name([curve UTF8String]);
  }

  if (!node.curve) {
    memzero(&node, sizeof(HDNode));
    @throw [NSException exceptionWithName:@"Error" reason:@"curve error" userInfo:nil];
  }

  BOOL private_derive = data.private_derive();

  uint32_t *path_arr = (uint32_t *) malloc(sizeof(uint32_t) * [path count]);
  if (!path_arr) {
    @throw [NSException exceptionWithName:@"Error" reason:@"Memory allocation failed" userInfo:nil];
  }
  
  for (int i = 0; i < [path count]; i++) {
    path_arr[i] = [[path objectAtIndex:i] unsignedIntValue];
  }
  
  int success = cryptolib::hdNodeDerive(&node, private_derive, [path count], path_arr);
  free(path_arr);
  
  if (success != 1) {
    memzero(&node, sizeof(HDNode));
    @throw [NSException exceptionWithName:@"Error" reason:@"derive error" userInfo:nil];
  }
  
  uint32_t fp = hdnode_fingerprint(&node);

  NSDictionary *result = @{
    @"depth": @(node.depth),
    @"child_num": @(node.child_num),
    @"chain_code": [[NSData dataWithBytes:node.chain_code length:sizeof(node.chain_code)] base64EncodedStringWithOptions:0],
    @"private_key": [[NSData dataWithBytes:node.private_key length:sizeof(node.private_key)] base64EncodedStringWithOptions:0],
    @"public_key": [[NSData dataWithBytes:node.public_key length:sizeof(node.public_key)] base64EncodedStringWithOptions:0],
    @"fingerprint": @(fp),
    @"curve": curve,
    @"private_derive": @(private_derive)
  };
  
  memzero(&node, sizeof(HDNode));
  fp = 0;

  return result;
}
#else
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hdNodeDerive:(NSDictionary *)data
  path:(NSArray<NSNumber *> *)path
) {
  HDNode node = {};
  
  if (data[@"depth"]) {
    node.depth = [data[@"depth"] unsignedIntValue];
  }

  if (data[@"child_num"]) {
    node.child_num = [data[@"child_num"] unsignedIntValue];
  }

  if (data[@"chain_code"]) {
    NSData *chain_code = [[NSData alloc] initWithBase64EncodedString:data[@"chain_code"] options:0];
    if ([chain_code length] == sizeof(node.chain_code)) {
      memcpy(&node.chain_code, [chain_code bytes], sizeof(node.chain_code));
    }
  }

  if (data[@"private_key"]) {
    NSData *private_key = [[NSData alloc] initWithBase64EncodedString:data[@"private_key"] options:0];
    if ([private_key length] == sizeof(node.private_key)) {
      memcpy(&node.private_key, [private_key bytes], sizeof(node.private_key));
    }
  }

  if (data[@"public_key"]) {
    NSData *public_key = [[NSData alloc] initWithBase64EncodedString:data[@"public_key"] options:0];
    if ([public_key length] == sizeof(node.public_key)) {
      memcpy(&node.public_key, [public_key bytes], sizeof(node.public_key));
    }
  }

  NSString *curve = data[@"curve"];

  if (curve) {
    node.curve = get_curve_by_name([curve UTF8String]);
  }

  if (!node.curve) {
    memzero(&node, sizeof(HDNode));
    @throw [NSException exceptionWithName:@"Error" reason:@"curve error" userInfo:nil];
  }
    
  BOOL private_derive = [data[@"private_derive"] boolValue];

  uint32_t *path_arr = (uint32_t *) malloc(sizeof(uint32_t) * [path count]);
  if (!path_arr) {
    @throw [NSException exceptionWithName:@"Error" reason:@"Memory allocation failed" userInfo:nil];
  }
  
  for (int i = 0; i < [path count]; i++) {
    path_arr[i] = [[path objectAtIndex:i] unsignedIntValue];
  }
  
  int success = cryptolib::hdNodeDerive(&node, private_derive, [path count], path_arr);
  free(path_arr);
  
  if (success != 1) {
    memzero(&node, sizeof(HDNode));
    @throw [NSException exceptionWithName:@"Error" reason:@"derive error" userInfo:nil];
  }
  
  uint32_t fp = hdnode_fingerprint(&node);

  NSDictionary *result = @{
    @"depth": @(node.depth),
    @"child_num": @(node.child_num),
    @"chain_code": [[NSData dataWithBytes:node.chain_code length:sizeof(node.chain_code)] base64EncodedStringWithOptions:0],
    @"private_key": [[NSData dataWithBytes:node.private_key length:sizeof(node.private_key)] base64EncodedStringWithOptions:0],
    @"public_key": [[NSData dataWithBytes:node.public_key length:sizeof(node.public_key)] base64EncodedStringWithOptions:0],
    @"fingerprint": @(fp),
    @"curve": curve,
    @"private_derive": @(private_derive)
  };
  
  memzero(&node, sizeof(HDNode));
  fp = 0;

  return result;
}
#endif

RCT_EXPORT_METHOD(
  ecdsaRandomPrivate:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  uint8_t *priv = (uint8_t *) malloc(ECDSA_KEY_SIZE);
  
  cryptolib::ecdsaRandomPrivate(priv);

  NSData *result = [NSData dataWithBytes:priv length:ECDSA_KEY_SIZE];
  
  memzero(priv, ECDSA_KEY_SIZE);
  free(priv);

  resolve([result base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaValidatePrivate:(NSString *)priv
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  if ([raw_priv length] != ECDSA_KEY_SIZE) {
    return [NSNumber numberWithInt: 0];
  }
    
  if (!cryptolib::ecdsaValidatePrivate((uint8_t *)[raw_priv bytes])) {
    return [NSNumber numberWithInt: 0];
  }
  
  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaGetPublic:(NSString *)priv
  compact:(BOOL)compact
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  uint8_t *pub;
  int pub_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  pub = (uint8_t *) malloc(pub_size);

  if (!cryptolib::ecdsaGetPublic((uint8_t *)[raw_priv bytes], pub, compact)) {
    free(pub);
    @throw [NSException exceptionWithName:@"Error" reason:@"pub key error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:pub length:pub_size];
  
  memzero(pub, pub_size);
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  free(pub);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaReadPublic:(NSString *)pub
  compact:(BOOL)compact
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];

  uint8_t *out_pub;
  int pub_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  out_pub = (uint8_t *) malloc(pub_size);

  if (!cryptolib::ecdsaReadPublic((uint8_t *)[raw_pub bytes], out_pub, compact)) {
    free(out_pub);
    @throw [NSException exceptionWithName:@"Error" reason:@"pub key error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:out_pub length:pub_size];
  
  memzero(out_pub, pub_size);
  memzero((void *)[raw_pub bytes], [raw_pub length]);
  free(out_pub);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaValidatePublic:(NSString *)pub
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];

  if ([raw_pub length] != ECDSA_KEY_33_SIZE && [raw_pub length] != ECDSA_KEY_65_SIZE) {
    return [NSNumber numberWithInt: 0];
  }

  if (!cryptolib::ecdsaValidatePublic((uint8_t *)[raw_pub bytes])) {
    return [NSNumber numberWithInt: 0];
  }

  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaRecover:(NSString *)sig
  recId:(double)recId
  digest:(NSString *)digest
) {
  NSData *raw_sig = [[NSData alloc]initWithBase64EncodedString:sig options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  uint8_t *pub = (uint8_t *) malloc(ECDSA_KEY_65_SIZE);

  if (!cryptolib::ecdsaRecover((uint8_t *)[raw_sig bytes], (int)recId, (uint8_t *)[raw_digest bytes], pub)) {
    free(pub);
    @throw [NSException exceptionWithName:@"Error" reason:@"recover error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:pub length:ECDSA_KEY_65_SIZE];
  
  free(pub);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaEcdh:(NSString *)pub
  priv:(NSString *)priv
  compact:(BOOL)compact
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  int ecdh_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  uint8_t *ecdh = (uint8_t *) malloc(ecdh_size);

  if (!cryptolib::ecdsaEcdh((uint8_t *)[raw_pub bytes], (uint8_t *)[raw_priv bytes], ecdh, compact)) {
    free(ecdh);
    @throw [NSException exceptionWithName:@"Error" reason:@"ecdh error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:ecdh length:ecdh_size];
  
  memzero(ecdh, ecdh_size);
  memzero((void *)[raw_pub bytes], [raw_pub length]);
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  free(ecdh);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaVerify:(NSString *)pub
  sign:(NSString *)sign
  digest:(NSString *)digest
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_sign = [[NSData alloc]initWithBase64EncodedString:sign options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  if (!cryptolib::ecdsaVerify(
    (uint8_t *)[raw_pub bytes],
    (uint8_t *)[raw_sign bytes],
    (uint8_t *)[raw_digest bytes]
  )) {
    return [NSNumber numberWithInt: 0];
  }

  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaSign:(NSString *)priv
  digest:(NSString *)digest
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  uint8_t *sign = (uint8_t *) malloc(ECDSA_SIGN_SIZE);

  if (!cryptolib::ecdsaSign((uint8_t *)[raw_priv bytes], (uint8_t *)[raw_digest bytes], sign)) {
    free(sign);
    @throw [NSException exceptionWithName:@"Error" reason:@"sign error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:sign length:ECDSA_SIGN_SIZE];
  
  memzero(sign, ECDSA_SIGN_SIZE);
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  memzero((void *)[raw_digest bytes], [raw_digest length]);
  free(sign);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_METHOD(
  ecdsaSignAsync:(NSString *)priv
  digest:(NSString *)digest
  resolve:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  uint8_t *sign = (uint8_t *) malloc(ECDSA_SIGN_SIZE);

  if (!cryptolib::ecdsaSign((uint8_t *)[raw_priv bytes], (uint8_t *)[raw_digest bytes], sign)) {
    free(sign);
    reject(@"Error", @"sign error", nil);
    return;
  }

  NSData *result = [NSData dataWithBytes:sign length:ECDSA_SIGN_SIZE];
  
  memzero(sign, ECDSA_SIGN_SIZE);
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  memzero((void *)[raw_digest bytes], [raw_digest length]);
  free(sign);

  resolve([result base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_METHOD(
  encrypt:(NSString *)key
  iv:(NSString *)iv
  data:(NSString *)data
  paddingMode:(double)paddingMode
  resolve:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  NSData *raw_key = [[NSData alloc]initWithBase64EncodedString:key options:0];
  NSData *raw_iv = [[NSData alloc]initWithBase64EncodedString:iv options:0];
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];

  aes_encrypt_ctx ctx;

  if (aes_encrypt_key256((uint8_t *)[raw_key bytes], &ctx) == EXIT_FAILURE) {
    reject(@"failure", @"invalid key", nil);
    return;
  }

  uint8_t *iv_bytes = (uint8_t *)[raw_iv bytes];
  uint8_t *data_bytes = (uint8_t *)[raw_data bytes];
  size_t dataSize = [raw_data length];

  size_t padding = cryptolib::paddingSize(
    dataSize,
    AES_BLOCK_SIZE,
    (AESPaddingMode) paddingMode
  );
  size_t resultSize = dataSize + padding;
  size_t idx;

  uint8_t *result = (uint8_t *) malloc(resultSize);

  for (idx = 0; idx < resultSize - AES_BLOCK_SIZE; idx += AES_BLOCK_SIZE) {
    aes_cbc_encrypt(data_bytes + idx, result + idx, AES_BLOCK_SIZE, iv_bytes, &ctx);
  }

  if (idx < resultSize) {
    uint8_t padded[AES_BLOCK_SIZE] = {0};
    if ((AESPaddingMode) paddingMode == AESPaddingModePKCS7) {
      std::memset(padded, static_cast<int>(padding), AES_BLOCK_SIZE);
    }
    std::memcpy(padded, data_bytes + idx, dataSize - idx);
    aes_cbc_encrypt(padded, result + idx, AES_BLOCK_SIZE, iv_bytes, &ctx);
  }

  NSData *out = [NSData dataWithBytes:result length:resultSize];
  
  memzero((void *)[raw_key bytes], [raw_key length]);
  memzero((void *)[raw_iv bytes], [raw_iv length]);
  memzero((void *)[raw_data bytes], [raw_data length]);

  free(result);

  resolve([out base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_METHOD(
  decrypt:(NSString *)key
  iv:(NSString *)iv
  data:(NSString *)data
  paddingMode:(double)paddingMode
  resolve:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  NSData *raw_key = [[NSData alloc]initWithBase64EncodedString:key options:0];
  NSData *raw_iv = [[NSData alloc]initWithBase64EncodedString:iv options:0];
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];

  uint8_t *iv_bytes = (uint8_t *)[raw_iv bytes];
  uint8_t *data_bytes = (uint8_t *)[raw_data bytes];
  size_t dataSize = [raw_data length];

  if (dataSize % AES_BLOCK_SIZE != 0) {
    reject(@"failure", @"data size", nil);
    return;
  }

  aes_decrypt_ctx ctx;

  if (aes_decrypt_key256((uint8_t *)[raw_key bytes], &ctx) == EXIT_FAILURE) {
    reject(@"failure", @"invalid key", nil);
    return;
  }

  uint8_t *result = (uint8_t *) malloc(dataSize);

  for (size_t i = 0; i < dataSize; i += AES_BLOCK_SIZE) {
    aes_cbc_decrypt(data_bytes + i, result + i, AES_BLOCK_SIZE, iv_bytes, &ctx);
  }

  size_t resultSize = dataSize;

  if ((AESPaddingMode) paddingMode == AESPaddingModePKCS7 && dataSize > 0) {
    size_t paddingSize = result[dataSize - 1];
    if (paddingSize <= dataSize) {
      resultSize = resultSize - paddingSize;
    }
  }

  NSData *out = [NSData dataWithBytes:result length:resultSize];
  
  memzero((void *)[raw_key bytes], [raw_key length]);
  memzero((void *)[raw_iv bytes], [raw_iv length]);
  memzero((void *)[raw_data bytes], [raw_data length]);

  free(result);

  resolve([out base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  schnorrGetPublic:(NSString *)priv
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      @throw [NSException exceptionWithName:@"Error" reason:@"context init error" userInfo:nil];
    }
  }

  uint8_t *pub = (uint8_t *) malloc(SCHNORR_PUBLIC_KEY_SIZE);

  if (zkp_bip340_get_public_key((uint8_t *)[raw_priv bytes], pub) == EXIT_FAILURE) {
    zkp_context_destroy();
    free(pub);
    @throw [NSException exceptionWithName:@"Error" reason:@"pub key error" userInfo:nil];
  }

  zkp_context_destroy();

  NSData *result = [NSData dataWithBytes:pub length:SCHNORR_PUBLIC_KEY_SIZE];
  
  memzero(pub, SCHNORR_PUBLIC_KEY_SIZE);
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  free(pub);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  schnorrSign:(NSString *)priv
  digest:(NSString *)digest
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      @throw [NSException exceptionWithName:@"Error" reason:@"context init error" userInfo:nil];
    }
  }

  uint8_t *sign = (uint8_t *) malloc(SCHNORR_SIGN_SIZE);

  if (zkp_bip340_sign_digest((uint8_t *)[raw_priv bytes], (uint8_t *)[raw_digest bytes], sign, 0) == EXIT_FAILURE) {
    zkp_context_destroy();
    free(sign);
    @throw [NSException exceptionWithName:@"Error" reason:@"sign error" userInfo:nil];
  }

  zkp_context_destroy();

  NSData *result = [NSData dataWithBytes:sign length:SCHNORR_SIGN_SIZE];
  
  memzero(sign, SCHNORR_SIGN_SIZE);
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  memzero((void *)[raw_digest bytes], [raw_digest length]);
  free(sign);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_METHOD(
  schnorrSignAsync:(NSString *)priv
  digest:(NSString *)digest
  resolve:(RCTPromiseResolveBlock)resolve
  reject:(RCTPromiseRejectBlock)reject
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      @throw [NSException exceptionWithName:@"Error" reason:@"context init error" userInfo:nil];
    }
  }

  uint8_t *sign = (uint8_t *) malloc(SCHNORR_SIGN_SIZE);

  if (zkp_bip340_sign_digest((uint8_t *)[raw_priv bytes], (uint8_t *)[raw_digest bytes], sign, 0) == EXIT_FAILURE) {
    zkp_context_destroy();
    free(sign);
    @throw [NSException exceptionWithName:@"Error" reason:@"sign error" userInfo:nil];
  }

  zkp_context_destroy();

  NSData *result = [NSData dataWithBytes:sign length:SCHNORR_SIGN_SIZE];
  
  memzero(sign, SCHNORR_SIGN_SIZE);
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  memzero((void *)[raw_digest bytes], [raw_digest length]);
  free(sign);

  resolve([result base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  schnorrVerify:(NSString *)pub
  sign:(NSString *)sign
  digest:(NSString *)digest
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_sign = [[NSData alloc]initWithBase64EncodedString:sign options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      @throw [NSException exceptionWithName:@"Error" reason:@"context init error" userInfo:nil];
    }
  }

  if (zkp_bip340_verify_digest(
    (uint8_t *)[raw_pub bytes],
    (uint8_t *)[raw_sign bytes],
    (uint8_t *)[raw_digest bytes]
  ) == EXIT_FAILURE) {
    zkp_context_destroy();
    return [NSNumber numberWithInt: 0];
  }

  zkp_context_destroy();
  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  schnorrTweakPublic:(NSString *)pub
  root:(NSString *)root
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_root = [[NSData alloc]initWithBase64EncodedString:root options:0];

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      @throw [NSException exceptionWithName:@"Error" reason:@"context init error" userInfo:nil];
    }
  }

  uint8_t *tweak = (uint8_t *) malloc(SCHNORR_PUBLIC_KEY_SIZE);

  if (zkp_bip340_tweak_public_key(
    (uint8_t *)[raw_pub bytes],
    (uint8_t *)[raw_root bytes],
    tweak
  ) == EXIT_FAILURE) {
    zkp_context_destroy();
    free(tweak);
    @throw [NSException exceptionWithName:@"Error" reason:@"tweak error" userInfo:nil];
  }

  zkp_context_destroy();
  
  NSData *result = [NSData dataWithBytes:tweak length:SCHNORR_PUBLIC_KEY_SIZE];
  
  free(tweak);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  schnorrTweakPrivate:(NSString *)priv
  root:(NSString *)root
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];
  NSData *raw_root = [[NSData alloc]initWithBase64EncodedString:root options:0];

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      @throw [NSException exceptionWithName:@"Error" reason:@"context init error" userInfo:nil];
    }
  }

  uint8_t *tweak = (uint8_t *) malloc(SCHNORR_PRIVATE_KEY_SIZE);

  if (zkp_bip340_tweak_private_key(
    (uint8_t *)[raw_priv bytes],
    (uint8_t *)[raw_root bytes],
    tweak
  ) == EXIT_FAILURE) {
    zkp_context_destroy();
    free(tweak);
    @throw [NSException exceptionWithName:@"Error" reason:@"tweak error" userInfo:nil];
  }

  zkp_context_destroy();
  
  NSData *result = [NSData dataWithBytes:tweak length:SCHNORR_PRIVATE_KEY_SIZE];
  
  free(tweak);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  schnorrVerifyPub:(NSString *)pub
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      @throw [NSException exceptionWithName:@"Error" reason:@"context init error" userInfo:nil];
    }
  }

  int result = zkp_bip340_verify_publickey(
    (uint8_t *)[raw_pub bytes]
  );

  zkp_context_destroy();

  if (result == EXIT_FAILURE) {
    return [NSNumber numberWithInt: 0];
  }

  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  xOnlyPointAddTweak:(NSString *)pub
  tweak:(NSString *)tweak
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_tweak = [[NSData alloc]initWithBase64EncodedString:tweak options:0];

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      @throw [NSException exceptionWithName:@"Error" reason:@"context init error" userInfo:nil];
    }
  }

  uint8_t *tweak_pub = (uint8_t *) malloc(SCHNORR_PUBLIC_KEY_SIZE);
  int parity = 0;

  if (zkp_bip340_xonly_point_add_tweak(
    (uint8_t *)[raw_pub bytes],
    (uint8_t *)[raw_tweak bytes],
    tweak_pub,
    &parity
  ) != 0) {
    zkp_context_destroy();
    free(tweak_pub);
    return NULL;
  }

  zkp_context_destroy();
  
  NSDictionary *result = @{
    @"parity": [NSNumber numberWithInt: parity],
    @"xOnlyPubkey": [
      [NSData dataWithBytes:tweak_pub length: SCHNORR_PUBLIC_KEY_SIZE]
      base64EncodedStringWithOptions:0
    ]
  };
  
  free(tweak_pub);

  return result;
}

// Don't compile this code when we build for the old architecture.
#ifdef RCT_NEW_ARCH_ENABLED
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeCryptoLibSpecJSI>(params);
}
#endif

@end

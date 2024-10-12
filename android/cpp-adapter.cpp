#include <jni.h>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include "react-native-crypto-lib.h"

#include "memzero.h"
#include "bip32.h"
#include "bip39.h"
#include "aes.h"
#include "zkp_bip340.h"
#include "zkp_context.h"

extern "C"
JNIEXPORT jdouble JNICALL
Java_com_cryptolib_CryptoLibModule_nativeRandomNumber(
  __attribute__((unused)) JNIEnv *env,
  __attribute__((unused)) jclass type
) {
  return (jdouble) cryptolib::randomNumber();
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeRandomBytes(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jint length
) {
  jbyte *bytes = (jbyte *) malloc(length);
  cryptolib::randomBytes(reinterpret_cast<uint8_t *>(bytes), length);

  jbyteArray result;
  result = env->NewByteArray(length);
  env->SetByteArrayRegion(result, 0, length, bytes);

  free(bytes);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeHash(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jint algorithm,
  jbyteArray data
) {
  jsize dataSize = env->GetArrayLength(data);
  jbyte *dataBytes = env->GetByteArrayElements(data, (jboolean *)false);

  jsize hashSize;

  switch (algorithm) {
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
      throw std::invalid_argument("unknown hash type");
  }

  jbyte *hash = (jbyte *) malloc(hashSize);
  cryptolib::hash(
    static_cast<HASH_TYPE>(algorithm),
    reinterpret_cast<uint8_t *>(dataBytes),
    dataSize,
    reinterpret_cast<uint8_t *>(hash)
  );

  jbyteArray result = env->NewByteArray(hashSize);
  env->SetByteArrayRegion(result, 0, hashSize, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeHmac(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jint algorithm,
  jbyteArray key,
  jbyteArray data
) {
  jsize keySize = env->GetArrayLength(key);
  jbyte *keyBytes = env->GetByteArrayElements(key, (jboolean *)false);
  jsize dataSize = env->GetArrayLength(data);
  jbyte *dataBytes = env->GetByteArrayElements(data, (jboolean *)false);

  jsize hashSize;

  switch (algorithm) {
    case SHA256:
      hashSize = 32;
      break;
    case SHA512:
      hashSize = 64;
      break;

    default:
      throw std::invalid_argument("unknown hash type");
  }

  jbyte *hash = (jbyte *) malloc(hashSize);
  cryptolib::hmac(
    static_cast<HASH_TYPE>(algorithm),
    reinterpret_cast<uint8_t *>(keyBytes),
    keySize,
    reinterpret_cast<uint8_t *>(dataBytes),
    dataSize,
    reinterpret_cast<uint8_t *>(hash)
  );

  jbyteArray result = env->NewByteArray(hashSize);
  env->SetByteArrayRegion(result, 0, hashSize, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativePbkdf2(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jint algorithm,
  jbyteArray pass,
  jbyteArray salt,
  jint iterations,
  jint keyLength
) {
  jsize pass_length = env->GetArrayLength(pass);
  jbyte *raw_pass = env->GetByteArrayElements(pass, (jboolean *)false);
  jsize salt_length = env->GetArrayLength(salt);
  jbyte *raw_salt = env->GetByteArrayElements(salt, (jboolean *)false);

  jbyte *key = (jbyte *) malloc(keyLength);

  cryptolib::pbkdf2(
    static_cast<HASH_TYPE>(algorithm),
    reinterpret_cast<uint8_t *>(raw_pass), pass_length,
    reinterpret_cast<uint8_t *>(raw_salt), salt_length,
    iterations,
    reinterpret_cast<uint8_t *>(key), keyLength
  );

  jbyteArray result = env->NewByteArray(keyLength);
  env->SetByteArrayRegion(result, 0, keyLength, key);

  free(key);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeMnemonicToSeed(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jstring mnemonic,
  const jstring passphrase
) {
  const char *raw_mnemonic = env->GetStringUTFChars(mnemonic, 0);
  const char *raw_passphrase = env->GetStringUTFChars(passphrase, 0);
  jbyte *seed = (jbyte *) malloc(64);

  cryptolib::mnemonicToSeed(raw_mnemonic, raw_passphrase, reinterpret_cast<uint8_t *>(seed));

  jbyteArray result = env->NewByteArray(64);
  env->SetByteArrayRegion(result, 0, 64, seed);
  free(seed);

  return result;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_cryptolib_CryptoLibModule_nativeGenerateMnemonic(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jint strength
) {
  jstring result = env->NewStringUTF(cryptolib::generateMnemonic((int)strength));
  mnemonic_clear();
  return result;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_cryptolib_CryptoLibModule_nativeValidateMnemonic(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jstring mnemonic
) {
  return (jint) cryptolib::validateMnemonic(env->GetStringUTFChars(mnemonic, (jboolean *)false));
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_cryptolib_CryptoLibModule_nativeHdNodeFromSeed(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jstring curve,
  const jbyteArray seed
) {
  const uint8_t *raw_seed = (uint8_t *) env->GetByteArrayElements(seed, (jboolean *)false);

  HDNode node = {};
  int success = hdnode_from_seed(
    raw_seed,
    env->GetArrayLength(seed),
    env->GetStringUTFChars(curve, (jboolean *)false),
    &node
  );

  if (success != 1) {
    return NULL;
  }

  uint32_t fp = hdnode_fingerprint(&node);

  jclass node_class = env->FindClass("com/cryptolib/CryptoLibHDNode");
  jfieldID depth_field = env->GetFieldID(node_class, "depth", "D");
  jfieldID child_num_field = env->GetFieldID(node_class, "child_num", "D");
  jfieldID chain_code_field = env->GetFieldID(node_class, "chain_code", "[B");
  jfieldID private_key_field = env->GetFieldID(node_class, "private_key", "[B");
  jfieldID public_key_field = env->GetFieldID(node_class, "public_key", "[B");
  jfieldID fingerprint_field = env->GetFieldID(node_class, "fingerprint", "D");
  jfieldID curve_field = env->GetFieldID(node_class, "curve", "Ljava/lang/String;");
  jfieldID private_derive_field = env->GetFieldID(node_class, "private_derive", "Z");

  jobject result = env->AllocObject(node_class);

  env->SetDoubleField(result, depth_field, (jdouble) node.depth);
  env->SetDoubleField(result, child_num_field, (jdouble) node.child_num);

  jbyteArray chain_code = env->NewByteArray(sizeof(node.chain_code));
  env->SetByteArrayRegion(chain_code, 0, sizeof(node.chain_code), (jbyte *) &node.chain_code);
  env->SetObjectField(result, chain_code_field, chain_code);

  jbyteArray private_key = env->NewByteArray(sizeof(node.private_key));
  env->SetByteArrayRegion(private_key, 0, sizeof(node.private_key), (jbyte *) &node.private_key);
  env->SetObjectField(result, private_key_field, private_key);

  jbyteArray public_key = env->NewByteArray(sizeof(node.public_key));
  env->SetByteArrayRegion(public_key, 0, sizeof(node.public_key), (jbyte *) &node.public_key);
  env->SetObjectField(result, public_key_field, public_key);
  
  env->SetDoubleField(result, fingerprint_field, (jdouble) fp);
  env->SetObjectField(result, curve_field, curve);

  env->SetBooleanField(result, private_derive_field, true);

  return result;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_cryptolib_CryptoLibModule_nativeHdNodeDerive(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jobject data,
  const jdoubleArray path
) {
  jclass node_class = env->FindClass("com/cryptolib/CryptoLibHDNode");
  jfieldID depth_field = env->GetFieldID(node_class, "depth", "D");
  jfieldID child_num_field = env->GetFieldID(node_class, "child_num", "D");
  jfieldID chain_code_field = env->GetFieldID(node_class, "chain_code", "[B");
  jfieldID private_key_field = env->GetFieldID(node_class, "private_key", "[B");
  jfieldID public_key_field = env->GetFieldID(node_class, "public_key", "[B");
  jfieldID fingerprint_field = env->GetFieldID(node_class, "fingerprint", "D");
  jfieldID curve_field = env->GetFieldID(node_class, "curve", "Ljava/lang/String;");
  jfieldID private_derive_field = env->GetFieldID(node_class, "private_derive", "Z");

  HDNode node = {};

  node.depth = (uint32_t) env->GetDoubleField(data, depth_field);
  node.child_num = (uint32_t) env->GetDoubleField(data, child_num_field);

  jbyteArray chain_code = (jbyteArray) env->GetObjectField(data, chain_code_field);
  env->GetByteArrayRegion(chain_code, 0, sizeof(node.chain_code), (jbyte *) &node.chain_code);

  jbyteArray private_key = (jbyteArray) env->GetObjectField(data, private_key_field);
  env->GetByteArrayRegion(private_key, 0, sizeof(node.private_key), (jbyte *) &node.private_key);

  jbyteArray public_key = (jbyteArray) env->GetObjectField(data, public_key_field);
  env->GetByteArrayRegion(public_key, 0, sizeof(node.public_key), (jbyte *) &node.public_key);

  jstring curve = (jstring) env->GetObjectField(data, curve_field);

  node.curve = get_curve_by_name(env->GetStringUTFChars(curve, (jboolean *)false));

  bool private_derive = env->GetBooleanField(data, private_derive_field);

  jdouble *path_items = env->GetDoubleArrayElements(path, (jboolean *)false);
  jsize path_items_count = env->GetArrayLength(path);

  int success;

  for (int i = 0; i < path_items_count; i++) {
    jdouble index = path_items[i];

    if (private_derive) {
      success = hdnode_private_ckd(&node, index);
      if (success == 1) {
        hdnode_fill_public_key(&node);
      }
    } else {
      success = hdnode_public_ckd(&node, index);
    }

    if (success != 1) {
      return NULL;
    }
  }

  uint32_t fp = hdnode_fingerprint(&node);

  jobject result = env->AllocObject(node_class);

  env->SetDoubleField(result, depth_field, (jdouble) node.depth);
  env->SetDoubleField(result, child_num_field, (jdouble) node.child_num);

  chain_code = env->NewByteArray(sizeof(node.chain_code));
  env->SetByteArrayRegion(chain_code, 0, sizeof(node.chain_code), (jbyte *) &node.chain_code);
  env->SetObjectField(result, chain_code_field, chain_code);

  private_key = env->NewByteArray(sizeof(node.private_key));
  env->SetByteArrayRegion(private_key, 0, sizeof(node.private_key), (jbyte *) &node.private_key);
  env->SetObjectField(result, private_key_field, private_key);

  public_key = env->NewByteArray(sizeof(node.public_key));
  env->SetByteArrayRegion(public_key, 0, sizeof(node.public_key), (jbyte *) &node.public_key);
  env->SetObjectField(result, public_key_field, public_key);
  
  env->SetDoubleField(result, fingerprint_field, (jdouble) fp);
  env->SetObjectField(result, curve_field, curve);

  env->SetBooleanField(result, private_derive_field, private_derive);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaRandomPrivate(
  JNIEnv *env,
  __attribute__((unused)) jclass type
) {
  jbyte *priv = (jbyte *) malloc(ECDSA_KEY_SIZE);

  cryptolib::ecdsaRandomPrivate(reinterpret_cast<uint8_t *>(priv));

  jbyteArray result = env->NewByteArray(ECDSA_KEY_SIZE);
  env->SetByteArrayRegion(result, 0, ECDSA_KEY_SIZE, priv);

  memzero(priv, ECDSA_KEY_SIZE);
  free(priv);

  return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaValidatePrivate(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray priv
) {
  uint8_t *raw_priv = (uint8_t *) env->GetByteArrayElements(priv, (jboolean *)false);
  return cryptolib::ecdsaValidatePrivate(raw_priv);
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaGetPublic(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray priv,
  jboolean compact
) {
  uint8_t *raw_priv = (uint8_t *) env->GetByteArrayElements(priv, (jboolean *)false);

  uint8_t *pub;
  int pub_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  pub = (uint8_t *) malloc(pub_size);

  if (!cryptolib::ecdsaGetPublic(raw_priv, pub, compact)) {
    memzero(raw_priv, ECDSA_KEY_SIZE);
    free(pub);
    return NULL;
  }

  jbyteArray result = env->NewByteArray(pub_size);
  env->SetByteArrayRegion(result, 0, pub_size, (jbyte *) pub);

  memzero(raw_priv, ECDSA_KEY_SIZE);
  free(pub);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaReadPublic(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray pub,
  jboolean compact
) {
  uint8_t *raw_pub = (uint8_t *) env->GetByteArrayElements(pub, (jboolean *)false);

  uint8_t *out_pub;
  int pub_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  out_pub = (uint8_t *) malloc(pub_size);

  if (!cryptolib::ecdsaReadPublic(raw_pub, out_pub, compact)) {
    free(out_pub);
    return NULL;
  }

  jbyteArray result = env->NewByteArray(pub_size);
  env->SetByteArrayRegion(result, 0, pub_size, (jbyte *) out_pub);

  free(out_pub);

  return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaValidatePublic(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray pub
) {
  uint8_t *raw_pub = (uint8_t *) env->GetByteArrayElements(pub, (jboolean *)false);
  return cryptolib::ecdsaValidatePublic(raw_pub);
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaRecover(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray sig,
  jint recId,
  jbyteArray digest
) {
  uint8_t *raw_sig = (uint8_t *) env->GetByteArrayElements(sig, (jboolean *)false);
  uint8_t *raw_digest = (uint8_t *) env->GetByteArrayElements(digest, (jboolean *)false);

  uint8_t *pub = (uint8_t *) malloc(ECDSA_KEY_65_SIZE);

  if (!cryptolib::ecdsaRecover(raw_sig, recId, raw_digest, pub)) {
    free(pub);
    return NULL;
  }

  jbyteArray result = env->NewByteArray(ECDSA_KEY_65_SIZE);
  env->SetByteArrayRegion(result, 0, ECDSA_KEY_65_SIZE, (jbyte *) pub);

  free(pub);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaEcdh(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray pub,
  jbyteArray priv,
  jboolean compact
) {
  uint8_t *raw_pub = (uint8_t *) env->GetByteArrayElements(pub, (jboolean *)false);
  uint8_t *raw_priv = (uint8_t *) env->GetByteArrayElements(priv, (jboolean *)false);

  uint8_t *ecdh;
  int pub_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  ecdh = (uint8_t *) malloc(pub_size);

  if (!cryptolib::ecdsaEcdh(raw_pub, raw_priv, ecdh, compact)) {
    memzero(raw_priv, ECDSA_KEY_SIZE);
    free(ecdh);
    return NULL;
  }

  jbyteArray result = env->NewByteArray(pub_size);
  env->SetByteArrayRegion(result, 0, pub_size, (jbyte *) ecdh);

  memzero(raw_priv, ECDSA_KEY_SIZE);
  memzero(ecdh, pub_size);
  free(ecdh);

  return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaVerify(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray pub,
  jbyteArray sig,
  jbyteArray digest
) {
  uint8_t *raw_pub = (uint8_t *) env->GetByteArrayElements(pub, (jboolean *)false);
  uint8_t *raw_sig = (uint8_t *) env->GetByteArrayElements(sig, (jboolean *)false);
  uint8_t *raw_digest = (uint8_t *) env->GetByteArrayElements(digest, (jboolean *)false);

  return cryptolib::ecdsaVerify(raw_pub, raw_sig, raw_digest);
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEcdsaSign(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray priv,
  jbyteArray digest
) {
  uint8_t *raw_priv = (uint8_t *) env->GetByteArrayElements(priv, (jboolean *)false);
  uint8_t *raw_digest = (uint8_t *) env->GetByteArrayElements(digest, (jboolean *)false);

  uint8_t *sign = (uint8_t *) malloc(ECDSA_SIGN_SIZE);

  if (!cryptolib::ecdsaSign(raw_priv, raw_digest, sign)) {
    memzero(raw_priv, ECDSA_KEY_SIZE);
    free(sign);
    return NULL;
  }

  jbyteArray result = env->NewByteArray(ECDSA_SIGN_SIZE);
  env->SetByteArrayRegion(result, 0, ECDSA_SIGN_SIZE, (jbyte *) sign);

  memzero(raw_priv, ECDSA_KEY_SIZE);
  free(sign);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeEncrypt(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray key,
  jbyteArray iv,
  jbyteArray data,
  jint paddingMode
) {
  uint8_t *key_bytes = (uint8_t *) env->GetByteArrayElements(key, (jboolean *)false);
  uint8_t *iv_bytes = (uint8_t *) env->GetByteArrayElements(iv, (jboolean *)false);
  uint8_t *data_bytes = (uint8_t *) env->GetByteArrayElements(data, (jboolean *)false);

  size_t dataSize = env->GetArrayLength(data);

  aes_encrypt_ctx ctx;

  if (aes_encrypt_key256(key_bytes, &ctx) == EXIT_FAILURE) {
    memzero(key_bytes, 32);
    memzero(iv_bytes, 16);
    memzero(data_bytes, dataSize);

    return NULL;
  }

  size_t padding = cryptolib::paddingSize(
    dataSize,
    AES_BLOCK_SIZE,
    static_cast<AESPaddingMode>(paddingMode)
  );
  size_t resultSize = dataSize + padding;
  size_t idx;

  uint8_t *result = (uint8_t *) malloc(resultSize);

  for (idx = 0; idx < resultSize - AES_BLOCK_SIZE; idx += AES_BLOCK_SIZE) {
    aes_cbc_encrypt(data_bytes + idx, result + idx, AES_BLOCK_SIZE, iv_bytes, &ctx);
  }

  if (idx < resultSize) {
    uint8_t padded[AES_BLOCK_SIZE] = {0};
    if (paddingMode == AESPaddingModePKCS7) {
      std::memset(padded, static_cast<int>(padding), AES_BLOCK_SIZE);
    }
    std::memcpy(padded, data_bytes + idx, dataSize - idx);
    aes_cbc_encrypt(padded, result + idx, AES_BLOCK_SIZE, iv_bytes, &ctx);
  }

  jbyteArray out = env->NewByteArray(resultSize);
  env->SetByteArrayRegion(out, 0, resultSize, (jbyte *) result);

  memzero(key_bytes, 32);
  memzero(iv_bytes, 16);
  memzero(data_bytes, dataSize);

  free(result);

  return out;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeDecrypt(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray key,
  jbyteArray iv,
  jbyteArray data,
  jint paddingMode
) {
  uint8_t *key_bytes = (uint8_t *) env->GetByteArrayElements(key, (jboolean *)false);
  uint8_t *iv_bytes = (uint8_t *) env->GetByteArrayElements(iv, (jboolean *)false);
  uint8_t *data_bytes = (uint8_t *) env->GetByteArrayElements(data, (jboolean *)false);

  size_t dataSize = env->GetArrayLength(data);

  if (dataSize % AES_BLOCK_SIZE != 0) {
    memzero(key_bytes, 32);
    memzero(iv_bytes, 16);
    return NULL;
  }

  aes_decrypt_ctx ctx;

  if (aes_decrypt_key256(key_bytes, &ctx) == EXIT_FAILURE) {
    memzero(key_bytes, 32);
    memzero(iv_bytes, 16);
    return NULL;
  }

  uint8_t *result = (uint8_t *) malloc(dataSize);

  for (size_t i = 0; i < dataSize; i += AES_BLOCK_SIZE) {
    aes_cbc_decrypt(data_bytes + i, result + i, AES_BLOCK_SIZE, iv_bytes, &ctx);
  }

  size_t resultSize = dataSize;

  if (paddingMode == AESPaddingModePKCS7 && dataSize > 0) {
    size_t paddingSize = result[dataSize - 1];
    if (paddingSize <= dataSize) {
      resultSize = resultSize - paddingSize;
    }
  }

  jbyteArray out = env->NewByteArray(resultSize);
  env->SetByteArrayRegion(out, 0, resultSize, (jbyte *) result);

  memzero(key_bytes, 32);
  memzero(iv_bytes, 16);

  free(result);

  return out;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeSchnorrGetPublic(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray priv
) {
  uint8_t *raw_priv = (uint8_t *) env->GetByteArrayElements(priv, (jboolean *)false);

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      throw std::invalid_argument("context init error");
    }
  }

  uint8_t *pub = (uint8_t *) malloc(SCHNORR_PUBLIC_KEY_SIZE);

  if (zkp_bip340_get_public_key(raw_priv, pub) == EXIT_FAILURE) {
    zkp_context_destroy();
    free(pub);
    return NULL;
  }

  zkp_context_destroy();

  jbyteArray result = env->NewByteArray(SCHNORR_PUBLIC_KEY_SIZE);
  env->SetByteArrayRegion(result, 0, SCHNORR_PUBLIC_KEY_SIZE, (jbyte *) pub);

  memzero(raw_priv, SCHNORR_PRIVATE_KEY_SIZE);
  free(pub);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeSchnorrSign(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray priv,
  jbyteArray digest
) {
  uint8_t *raw_priv = (uint8_t *) env->GetByteArrayElements(priv, (jboolean *)false);
  uint8_t *raw_digest = (uint8_t *) env->GetByteArrayElements(digest, (jboolean *)false);

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      throw std::invalid_argument("context init error");
    }
  }

  uint8_t *sign = (uint8_t *) malloc(SCHNORR_SIGN_SIZE);

  if (zkp_bip340_sign_digest(raw_priv, raw_digest, sign, 0) == EXIT_FAILURE) {
    memzero(raw_priv, SCHNORR_PRIVATE_KEY_SIZE);
    zkp_context_destroy();
    free(sign);
    return NULL;
  }

  zkp_context_destroy();

  jbyteArray result = env->NewByteArray(SCHNORR_SIGN_SIZE);
  env->SetByteArrayRegion(result, 0, SCHNORR_SIGN_SIZE, (jbyte *) sign);

  memzero(raw_priv, SCHNORR_PRIVATE_KEY_SIZE);
  free(sign);

  return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_cryptolib_CryptoLibModule_nativeSchnorrVerify(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray pub,
  jbyteArray sig,
  jbyteArray digest
) {
  uint8_t *raw_pub = (uint8_t *) env->GetByteArrayElements(pub, (jboolean *)false);
  uint8_t *raw_sig = (uint8_t *) env->GetByteArrayElements(sig, (jboolean *)false);
  uint8_t *raw_digest = (uint8_t *) env->GetByteArrayElements(digest, (jboolean *)false);

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      throw std::invalid_argument("context init error");
    }
  }

  if (zkp_bip340_verify_digest(
    raw_pub,
    raw_sig,
    raw_digest
  ) == EXIT_FAILURE) {
    zkp_context_destroy();
    return false;
  }

  zkp_context_destroy();
  return true;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeSchnorrTweakPublic(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray pub,
  jbyteArray root
) {
  uint8_t *raw_pub = (uint8_t *) env->GetByteArrayElements(pub, (jboolean *)false);
  uint8_t *raw_root = NULL;

  if (root != NULL) {
    raw_root = (uint8_t *) env->GetByteArrayElements(root, (jboolean *)false);
  }

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      throw std::invalid_argument("context init error");
    }
  }

  uint8_t *tweak = (uint8_t *) malloc(SCHNORR_PUBLIC_KEY_SIZE);

  if (zkp_bip340_tweak_public_key(
    raw_pub,
    raw_root,
    tweak
  ) == EXIT_FAILURE) {
    zkp_context_destroy();
    free(tweak);
    return NULL;
  }

  zkp_context_destroy();

  jbyteArray result = env->NewByteArray(SCHNORR_PUBLIC_KEY_SIZE);
  env->SetByteArrayRegion(result, 0, SCHNORR_PUBLIC_KEY_SIZE, (jbyte *) tweak);

  free(tweak);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cryptolib_CryptoLibModule_nativeSchnorrTweakPrivate(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray priv,
  jbyteArray root
) {
  uint8_t *raw_priv = (uint8_t *) env->GetByteArrayElements(priv, (jboolean *)false);
  uint8_t *raw_root = NULL;

  if (root != NULL) {
    raw_root = (uint8_t *) env->GetByteArrayElements(root, (jboolean *)false);
  }

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      throw std::invalid_argument("context init error");
    }
  }

  uint8_t *tweak = (uint8_t *) malloc(SCHNORR_PRIVATE_KEY_SIZE);

  if (zkp_bip340_tweak_private_key(
    raw_priv,
    raw_root,
    tweak
  ) == EXIT_FAILURE) {
    memzero(raw_priv, SCHNORR_PRIVATE_KEY_SIZE);
    zkp_context_destroy();
    free(tweak);
    return NULL;
  }

  zkp_context_destroy();

  jbyteArray result = env->NewByteArray(SCHNORR_PRIVATE_KEY_SIZE);
  env->SetByteArrayRegion(result, 0, SCHNORR_PRIVATE_KEY_SIZE, (jbyte *) tweak);

  memzero(raw_priv, SCHNORR_PRIVATE_KEY_SIZE);
  free(tweak);

  return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_cryptolib_CryptoLibModule_nativeSchnorrVerifyPub(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray pub
) {
  uint8_t *raw_pub = (uint8_t *) env->GetByteArrayElements(pub, (jboolean *)false);

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      throw std::invalid_argument("context init error");
    }
  }

  int result = zkp_bip340_verify_publickey(
    raw_pub
  );

  zkp_context_destroy();

  if (result == EXIT_FAILURE) {
    return false;
  }

  return true;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_cryptolib_CryptoLibModule_nativeXOnlyPointAddTweak(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jbyteArray pub,
  jbyteArray tweak
) {
  uint8_t *raw_pub = (uint8_t *) env->GetByteArrayElements(pub, (jboolean *)false);
  uint8_t *raw_tweak = (uint8_t *) env->GetByteArrayElements(tweak, (jboolean *)false);

  jclass node_class = env->FindClass("com/cryptolib/CryptoLibXOnlyPointAddTweak");
  jfieldID parity_field = env->GetFieldID(node_class, "parity", "D");
  jfieldID xOnlyPubkey_field = env->GetFieldID(node_class, "xOnlyPubkey", "[B");

  if (!zkp_context_is_initialized()) {
    if (zkp_context_init() == EXIT_FAILURE) {
      throw std::invalid_argument("context init error");
    }
  }

  uint8_t *tweak_pub = (uint8_t *) malloc(SCHNORR_PUBLIC_KEY_SIZE);
  int parity = 0;

  if (zkp_bip340_xonly_point_add_tweak(
    raw_pub,
    raw_tweak,
    tweak_pub,
    &parity
  ) != 0) {
    zkp_context_destroy();
    free(tweak_pub);
    return NULL;
  }

  zkp_context_destroy();

  jobject result = env->AllocObject(node_class);
  
  env->SetDoubleField(result, parity_field, (jdouble) parity);

  jbyteArray xOnlyPubkey = env->NewByteArray(SCHNORR_PUBLIC_KEY_SIZE);
  env->SetByteArrayRegion(xOnlyPubkey, 0, SCHNORR_PUBLIC_KEY_SIZE, (jbyte *) tweak_pub);
  env->SetObjectField(result, xOnlyPubkey_field, xOnlyPubkey);

  free(tweak_pub);

  return result;
}

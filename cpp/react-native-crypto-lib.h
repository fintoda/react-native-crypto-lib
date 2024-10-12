#ifndef CRYPTOLIB_H
#define CRYPTOLIB_H

#include <stdint.h>
#include <stddef.h>

enum HASH_TYPE {
  SHA1,
  SHA256,
  SHA512,
  SHA3_256,
  SHA3_512,
  KECCAK_256,
  KECCAK_512,
  RIPEMD160,
  HASH256,
  HASH160
};

enum BIP32_DERIVE_TYPE {
  DERIVE_PRIVATE,
  DERIVE_PUBLIC,
};

enum AESPaddingMode {
  AESPaddingModeZero = 0,
  AESPaddingModePKCS7 = 1,
};

#define ECDSA_KEY_SIZE 32
#define ECDSA_KEY_33_SIZE 33
#define ECDSA_KEY_65_SIZE 65
#define ECDSA_SIGN_SIZE 65

#define SCHNORR_PRIVATE_KEY_SIZE 32
#define SCHNORR_PUBLIC_KEY_SIZE 32
#define SCHNORR_SIGN_SIZE 64

namespace cryptolib {
  // rng
  double randomNumber();
  void randomBytes(uint8_t *buf, size_t len);

  // digest
  void hash(HASH_TYPE algorithm, uint8_t *data, size_t len, uint8_t *hash);
  void hmac(
    HASH_TYPE algorithm,
    uint8_t *key, size_t keySize,
    uint8_t *data, size_t dataSize,
    uint8_t *hash
  );
  void pbkdf2(
    HASH_TYPE algorithm,
    uint8_t *pass, size_t passSize,
    uint8_t *salt, size_t saltSize,
    uint32_t iterations,
    uint8_t *hash, size_t hashSize
  );

  // bip39
  void mnemonicToSeed(const char *mnemonic, const char *passphrase, uint8_t *seed);
  const char *generateMnemonic(int strength);
  int validateMnemonic(const char *mnemonic);

  // ECDSA
  void ecdsaRandomPrivate(uint8_t *pk);
  bool ecdsaValidatePrivate(uint8_t *pk);
  bool ecdsaGetPublic(uint8_t *pk, uint8_t *out, bool compact);
  bool ecdsaReadPublic(uint8_t *pub, uint8_t *out, bool compact);
  bool ecdsaValidatePublic(uint8_t *pub);
  bool ecdsaRecover(uint8_t *sig, int recId, uint8_t *digest, uint8_t *out);
  bool ecdsaEcdh(uint8_t *pub, uint8_t *pk, uint8_t *out, bool compact);
  bool ecdsaVerify(uint8_t *pub, uint8_t *sig, uint8_t *digest);
  bool ecdsaSign(uint8_t *pk, uint8_t *digest, uint8_t *out);

  // AES
  size_t paddingSize(size_t origSize, size_t blockSize, AESPaddingMode paddingMode);
}

#endif /* CRYPTOLIB_H */

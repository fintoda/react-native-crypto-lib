#include "react-native-crypto-lib.h"

#include <stdexcept>

#include "options.h"
#include "memzero.h"
#include "rand.h"
#include "sha2.h"
#include "sha3.h"
#include "ripemd160.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "bip39.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "bignum.h"
#include "aes.h"

namespace cryptolib {
	double randomNumber() {
		return random32();
	}

	void randomBytes(uint8_t *buf, size_t len) {
		random_buffer(buf, len);
	}

	void hash(HASH_TYPE algorithm, uint8_t *data, size_t len, uint8_t *hash) {
		switch (algorithm) {
			case SHA1:
				sha1_Raw(data, len, hash);
				break;
			case SHA256:
				sha256_Raw(data, len, hash);
				break;
			case SHA512:
				sha512_Raw(data, len, hash);
				break;
			case SHA3_256:
				sha3_256(data, len, hash);
				break;
			case SHA3_512:
				sha3_512(data, len, hash);
				break;
			case KECCAK_256:
				keccak_256(data, len, hash);
				break;
			case KECCAK_512:
				keccak_512(data, len, hash);
				break;
			case RIPEMD160:
				ripemd160(data, len, hash);
				break;
			case HASH256:
				sha256_Raw(data, len, hash);
				sha256_Raw(hash, SHA256_DIGEST_LENGTH, hash);
				break;
			case HASH160:
				uint8_t *tmp[SHA256_DIGEST_LENGTH];
				sha256_Raw(data, len, reinterpret_cast<uint8_t *>(tmp));
				ripemd160(reinterpret_cast<uint8_t *>(tmp), SHA256_DIGEST_LENGTH, hash);
				break;
			
			default:
				throw std::invalid_argument("unknown hash type");
				break;
		}
	}

	void hmac(
		HASH_TYPE algorithm,
		uint8_t *key,
		size_t keySize,
		uint8_t *data,
		size_t dataSize,
		uint8_t *hash
	) {
		switch (algorithm) {
			case SHA256:
				hmac_sha256(
					key, keySize,
					data, dataSize,
					hash
				);
				break;
			case SHA512:
				hmac_sha512(
					key, keySize,
					data, dataSize,
					hash
				);
				break;
			
			default:
				throw std::invalid_argument("unknown hash type");
				break;
		}
	}

	void pbkdf2(
		HASH_TYPE algorithm,
		uint8_t *pass, size_t passSize,
    uint8_t *salt, size_t saltSize,
    uint32_t iterations,
    uint8_t *key, size_t keySize
	) {
		switch (algorithm) {
			case SHA256:
				pbkdf2_hmac_sha256(
					pass, passSize,
					salt, saltSize,
					iterations,
					key, keySize
				);
				break;
			case SHA512:
				pbkdf2_hmac_sha512(
					pass, passSize,
					salt, saltSize,
					iterations,
					key, keySize
				);
				break;
			
			default:
				throw std::invalid_argument("unknown hash type");
				break;
		}
	}

	void mnemonicToSeed(const char *mnemonic, const char *passphrase, uint8_t *seed) {
		mnemonic_to_seed(mnemonic, passphrase, seed, 0);
	}

	const char *generateMnemonic(int strength) {
		return mnemonic_generate(strength);
	}

	int validateMnemonic(const char *mnemonic) {
		return mnemonic_check(mnemonic);
	}

	void ecdsaRandomPrivate(uint8_t *pk) {
		bignum256 p = {0};

		while(true) {
			random_buffer(pk, 32);
			bn_read_be(pk, &p);
			if (!bn_is_zero(&p) && bn_is_less(&p, &secp256k1.order)) {
				break;
			}
		}

		memzero(&p, sizeof(bignum256));
	}

	bool ecdsaValidatePrivate(uint8_t *pk) {
		bignum256 p = {0};
		bn_read_be(pk, &p);
		if (bn_is_zero(&p) || (!bn_is_less(&p, &secp256k1.order))) {
			return false;
		}
		return true;
	}

	bool ecdsaGetPublic(uint8_t *pk, uint8_t *out, bool compact) {
		int err = 0;

		if (compact) {
			err = ecdsa_get_public_key33(&secp256k1, pk, out);
		} else {
			err = ecdsa_get_public_key65(&secp256k1, pk, out);
		}

		return err == 0;
	}

	bool ecdsaReadPublic(uint8_t *pub, uint8_t *out, bool compact) {
		curve_point pub_point = {};

		if (ecdsa_read_pubkey(&secp256k1, pub, &pub_point) == 0) {
			return false;
		}

		if (compact) {
			out[0] = 0x02 | (pub_point.y.val[0] & 0x01);
    	bn_write_be(&pub_point.x, out + 1);
		} else {
			out[0] = 0x04;
			bn_write_be(&pub_point.x, out + 1);
			bn_write_be(&pub_point.y, out + 33);
		}

		memzero(&pub_point, sizeof(curve_point));

		return true;
	}

	bool ecdsaValidatePublic(uint8_t *pub) {
		curve_point pub_point = {};
		int result = ecdsa_read_pubkey(&secp256k1, pub, &pub_point);
		
		memzero(&pub_point, sizeof(curve_point));

		return result == 1;
	}

	bool ecdsaRecover(uint8_t *sig, int recId, uint8_t *digest, uint8_t *out) {
		int err = ecdsa_recover_pub_from_sig(&secp256k1, out, sig, digest, recId);
		if (err > 0) {
			return false;
		}
		return true;
	}

	bool ecdsaEcdh(uint8_t *pub, uint8_t *pk, uint8_t *out, bool compact) {
		int err = 0;

		if (compact) {
			uint8_t *ecdh = (uint8_t *) malloc(ECDSA_KEY_65_SIZE);
			err = ecdh_multiply(&secp256k1, pk, pub, ecdh);

			curve_point p = {};
    	bn_read_be(ecdh + 1, &(p.x));
    	bn_read_be(ecdh + 33, &(p.y));

			out[0] = 0x02 | (p.y.val[0] & 0x01);
    	bn_write_be(&(p.x), out + 1);
    	
			memzero(&p, sizeof(p));
			memzero(ecdh, ECDSA_KEY_65_SIZE);
			free(ecdh);
		} else {
			err = ecdh_multiply(&secp256k1, pk, pub, out);
		}

		if (err > 0) {
			return false;
		}

		return true;
	}

	bool ecdsaVerify(uint8_t *pub, uint8_t *sig, uint8_t *digest) {
		int err = ecdsa_verify_digest(&secp256k1, pub, sig, digest);
		if (err > 0) {
			return false;
		}
		return true;
	}

	bool ecdsaSign(uint8_t *pk, uint8_t *digest, uint8_t *out) {
		int err = ecdsa_sign_digest(&secp256k1, pk, digest, out + 1, out, 0);
		if (err > 0) {
			return false;
		}
		return true;
	}

	size_t paddingSize(size_t origSize, size_t blockSize, AESPaddingMode paddingMode) {
		if (origSize % blockSize == 0) {
			if (paddingMode == AESPaddingModePKCS7) {
				return blockSize;
			}
			return 0;
		}
		return blockSize - origSize % blockSize;
	}
}

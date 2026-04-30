cmake_minimum_required(VERSION 3.4.1)
project(ReactNativeCryptoLib)

set (CMAKE_VERBOSE_MAKEFILE OFF)

# Subset of vendor/trezor-crypto/crypto/ that we actually compile.
# Keep this list in sync with ReactNativeCryptoLib.podspec.
set(TREZOR_CRYPTO_SOURCES
    ../vendor/trezor-crypto/crypto/memzero.c
    ../vendor/trezor-crypto/crypto/sha2.c
    ../vendor/trezor-crypto/crypto/sha3.c
    ../vendor/trezor-crypto/crypto/ripemd160.c
    ../vendor/trezor-crypto/crypto/blake256.c
    ../vendor/trezor-crypto/crypto/blake2b.c
    ../vendor/trezor-crypto/crypto/blake2s.c
    ../vendor/trezor-crypto/crypto/groestl.c
    ../vendor/trezor-crypto/crypto/hmac.c
    ../vendor/trezor-crypto/crypto/pbkdf2.c
    ../vendor/trezor-crypto/crypto/bignum.c
    ../vendor/trezor-crypto/crypto/hasher.c
    ../vendor/trezor-crypto/crypto/address.c
    ../vendor/trezor-crypto/crypto/base58.c
    ../vendor/trezor-crypto/crypto/hmac_drbg.c
    ../vendor/trezor-crypto/crypto/rfc6979.c
    ../vendor/trezor-crypto/crypto/secp256k1.c
    ../vendor/trezor-crypto/crypto/nist256p1.c
    ../vendor/trezor-crypto/crypto/ecdsa.c
    ../vendor/trezor-crypto/crypto/curves.c
    ../vendor/trezor-crypto/crypto/bip32.c
    ../vendor/trezor-crypto/crypto/bip39.c
    ../vendor/trezor-crypto/crypto/bip39_english.c
    ../vendor/trezor-crypto/crypto/aes/aescrypt.c
    ../vendor/trezor-crypto/crypto/aes/aeskey.c
    ../vendor/trezor-crypto/crypto/aes/aestab.c
    ../vendor/trezor-crypto/crypto/aes/aes_modes.c
    ../vendor/trezor-crypto/crypto/aes/aesgcm.c
    ../vendor/trezor-crypto/crypto/aes/gf128mul.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/ed25519.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/ed25519-sha3.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/ed25519-keccak.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/ed25519-donna-impl-base.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/ed25519-donna-32bit-tables.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/ed25519-donna-basepoint-table.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/modm-donna-32bit.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/curve25519-donna-32bit.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/curve25519-donna-helpers.c
    ../vendor/trezor-crypto/crypto/ed25519-donna/curve25519-donna-scalarmult-base.c
    ../vendor/trezor-crypto/crypto/shamir.c
    ../vendor/trezor-crypto/crypto/slip39.c
    ../vendor/trezor-crypto/crypto/slip39_english.c
)

add_library(
    fintoda-react-native-crypto-lib    STATIC
    ../cpp/ReactNativeCryptoLibImpl.cpp
    ../cpp/Hash.cpp
    ../cpp/Mac.cpp
    ../cpp/Kdf.cpp
    ../cpp/Rng.cpp
    ../cpp/Ecdsa.cpp
    ../cpp/Schnorr.cpp
    ../cpp/Ed25519.cpp
    ../cpp/Ecc.cpp
    ../cpp/Aes.cpp
    ../cpp/Bip39.cpp
    ../cpp/Bip32.cpp
    ../cpp/Slip39.cpp
    ../cpp/SecureKV.cpp
    ../cpp/SecureKVSign.cpp
    ../cpp/SecureKVPassphrase.cpp
    ../cpp/SecureKVBackup.cpp
    ../cpp/Biometric.cpp
    src/main/cpp/SecureKVBackend_android.cpp
    src/main/cpp/BiometricBackend_android.cpp
    ${TREZOR_CRYPTO_SOURCES}
)

set_target_properties(
    fintoda-react-native-crypto-lib PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_include_directories(
    fintoda-react-native-crypto-lib    PUBLIC
    ../cpp
    ../vendor/trezor-crypto/crypto
    ../vendor/trezor-crypto/crypto/ed25519-donna
    ../vendor/trezor-crypto/crypto/aes
)

target_compile_definitions(
    fintoda-react-native-crypto-lib    PRIVATE
    USE_KECCAK=1
    AES_VAR=1
)

target_compile_options(
    fintoda-react-native-crypto-lib    PRIVATE
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -Wno-deprecated-volatile   # trezor-crypto uses volatile in a C-style
                                # pattern that C++20 deprecates; harmless
)

target_link_libraries(
    fintoda-react-native-crypto-lib    jsi
    reactnative
    fbjni
    react_codegen_ReactNativeCryptoLibSpec
)

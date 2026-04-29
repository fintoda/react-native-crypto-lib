require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

# Subset of vendor/trezor-crypto/crypto/ that we actually compile.
# Add files here as new algorithms are exposed. Keep this list explicit:
# we want the build to fail loudly if a dependency goes missing rather
# than glob in unrelated upstream code.
trezor_crypto_sources = %w[
  vendor/trezor-crypto/crypto/memzero.c
  vendor/trezor-crypto/crypto/sha2.c
  vendor/trezor-crypto/crypto/sha3.c
  vendor/trezor-crypto/crypto/ripemd160.c
  vendor/trezor-crypto/crypto/blake256.c
  vendor/trezor-crypto/crypto/blake2b.c
  vendor/trezor-crypto/crypto/blake2s.c
  vendor/trezor-crypto/crypto/groestl.c
  vendor/trezor-crypto/crypto/hmac.c
  vendor/trezor-crypto/crypto/pbkdf2.c
  vendor/trezor-crypto/crypto/bignum.c
  vendor/trezor-crypto/crypto/hasher.c
  vendor/trezor-crypto/crypto/address.c
  vendor/trezor-crypto/crypto/base58.c
  vendor/trezor-crypto/crypto/hmac_drbg.c
  vendor/trezor-crypto/crypto/rfc6979.c
  vendor/trezor-crypto/crypto/secp256k1.c
  vendor/trezor-crypto/crypto/nist256p1.c
  vendor/trezor-crypto/crypto/ecdsa.c
  vendor/trezor-crypto/crypto/curves.c
  vendor/trezor-crypto/crypto/bip32.c
  vendor/trezor-crypto/crypto/bip39.c
  vendor/trezor-crypto/crypto/bip39_english.c
  vendor/trezor-crypto/crypto/aes/aescrypt.c
  vendor/trezor-crypto/crypto/aes/aeskey.c
  vendor/trezor-crypto/crypto/aes/aestab.c
  vendor/trezor-crypto/crypto/aes/aes_modes.c
  vendor/trezor-crypto/crypto/aes/aesgcm.c
  vendor/trezor-crypto/crypto/aes/gf128mul.c
  vendor/trezor-crypto/crypto/ed25519-donna/ed25519.c
  vendor/trezor-crypto/crypto/ed25519-donna/ed25519-sha3.c
  vendor/trezor-crypto/crypto/ed25519-donna/ed25519-keccak.c
  vendor/trezor-crypto/crypto/ed25519-donna/ed25519-donna-impl-base.c
  vendor/trezor-crypto/crypto/ed25519-donna/ed25519-donna-32bit-tables.c
  vendor/trezor-crypto/crypto/ed25519-donna/ed25519-donna-basepoint-table.c
  vendor/trezor-crypto/crypto/ed25519-donna/modm-donna-32bit.c
  vendor/trezor-crypto/crypto/ed25519-donna/curve25519-donna-32bit.c
  vendor/trezor-crypto/crypto/ed25519-donna/curve25519-donna-helpers.c
  vendor/trezor-crypto/crypto/ed25519-donna/curve25519-donna-scalarmult-base.c
  vendor/trezor-crypto/crypto/shamir.c
  vendor/trezor-crypto/crypto/slip39.c
  vendor/trezor-crypto/crypto/slip39_english.c
]

Pod::Spec.new do |s|
  s.name         = "ReactNativeCryptoLib"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/fintoda/react-native-crypto-lib.git", :tag => "#{s.version}" }

  s.source_files = ["ios/**/*.{h,m,mm}",
                    "cpp/**/*.{hpp,cpp,c,h}",
                    "ios/generated/**/*.{h,cpp,mm}",
                    "vendor/trezor-crypto/crypto/*.h",
                    "vendor/trezor-crypto/crypto/ed25519-donna/*.h",
                    "vendor/trezor-crypto/crypto/aes/*.h"] + trezor_crypto_sources

  # Security: kSecClassGenericPassword wrappers for the secureKV module
  # live in ios/SecureKVBackend.mm. LocalAuthentication: SecAccessControl
  # / LAContext for the biometric accessControl variant.
  s.frameworks = "Security", "LocalAuthentication"

  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/ios/generated/ReactCodegen\" \"$(PODS_TARGET_SRCROOT)/ios/generated/ReactCodegen/ReactNativeCryptoLibSpec\" \"$(PODS_TARGET_SRCROOT)/cpp\" \"$(PODS_TARGET_SRCROOT)/vendor/trezor-crypto/crypto\" \"$(PODS_TARGET_SRCROOT)/vendor/trezor-crypto/crypto/ed25519-donna\" \"$(PODS_TARGET_SRCROOT)/vendor/trezor-crypto/crypto/aes\"",
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++20",
    "GCC_PREPROCESSOR_DEFINITIONS" => "$(inherited) USE_KECCAK=1 AES_VAR=1",
    "OTHER_CFLAGS" => "$(inherited) -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wno-deprecated-volatile",
  }

  install_modules_dependencies(s)
end

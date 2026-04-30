# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added

- Async (Promise-returning) variants for the heavy crypto primitives.
  `kdf.pbkdf2_sha256`, `kdf.pbkdf2_sha512`, `bip39.toSeed`,
  `slip39.generate`, `slip39.generateGroups`, and `slip39.combine` now
  run on a worker thread, keeping the JS thread responsive during
  multi-hundred-millisecond derivations.
- `*Sync` escape-hatch variants for each of the above
  (`pbkdf2_sha256Sync`, `toSeedSync`, `generateSync`, etc.) for callers
  that prefer synchronous returns.
- `secureKV` audit-driven hardening across all layers (see commit
  `a2d4041`): worker-thread dispatch for every secureKV/biometric thunk,
  per-call biometric prompt copy, iOS `kSecUseAuthenticationUISkip`
  for `has()`, Android API 28-29 silent downgrade for biometric
  validity windows, FQCN-based JNI exception mapping, on-device
  `BiometricCanceledError`.

### Changed

- **Breaking**: `kdf.pbkdf2_sha{256,512}`, `bip39.toSeed`, and
  `slip39.{generate,generateGroups,combine}` now return Promises.
  Migration:
  - preferred — `await` the call;
  - minimal — switch to the `*Sync` variant
    (e.g. `bip39.toSeedSync(mnemonic)`).
- iOS `BiometricBackend::authenticate` now times out after 120 s
  instead of waiting forever (mirrors the Android cap).
- Android secureKV biometric blob format carries a plaintext key
  prefix in the header so `secureKV.list()` can enumerate biometric
  entries without prompting.

## [0.9.0] - 2026-04-12

### Added

- SLIP-39 Shamir secret sharing: `generate`, `generateGroups`, `combine`, `validateMnemonic`
- Security hardening across all existing modules (`memzero` on all sensitive buffers)
- CLAUDE.md with project conventions and architecture documentation

### Fixed

- Resolved undici CVE-2025-22 by pinning to 6.24.0

### Changed

- Updated Podfile.lock for SLIP-39 vendor sources

## [0.8.0] - 2026-03-10

### Changed

- Complete rewrite with new native module architecture (JSI/Turbo Module)
- Vendored trezor-crypto as the C cryptography backend
- Synchronous, zero-copy ArrayBuffer API across JSI boundary

### Fixed

- Broken discussion URLs in CONTRIBUTING.md

## [0.7.4] - 2025-12-15

### Fixed

- iOS RNG implementation
- iOS Release build configuration
- BIP-32 derivation
- TypeScript type definitions
- Example Android build

## [0.5.4] - 2025-09-20

### Fixed

- iOS build issues

### Changed

- Migrated to New Architecture module

## [0.5.3] - 2025-09-15

### Fixed

- iOS build issues

## [0.5.1] - 2025-09-10

### Fixed

- Package `publishConfig.access` setting
- Package name
- Package `files` field

## [0.5.0] - 2025-09-05

### Added

- Initial release
- Hash functions: SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, Keccak-256, Keccak-512, RIPEMD-160, BLAKE256, BLAKE2b, BLAKE2s, Groestl-512
- MAC: HMAC-SHA256, HMAC-SHA512
- KDF: PBKDF2-SHA256, PBKDF2-SHA512, HKDF-SHA256, HKDF-SHA512
- RNG: cryptographically secure random bytes, uint32, uniform
- ECDSA: sign, verify, recover, ECDH (secp256k1, nist256p1)
- Schnorr: BIP-340 sign/verify, key tweaking
- Ed25519: sign/verify, X25519 key exchange
- AES: CBC, CTR, GCM (256-bit)
- BIP-39: mnemonic generation, validation, seed derivation
- BIP-32: HD key derivation, serialization
- ECC utilities: point arithmetic, private key tweaking
- WebCrypto polyfill (`getRandomValues`)

[0.9.0]: https://github.com/fintoda/react-native-crypto-lib/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/fintoda/react-native-crypto-lib/compare/v0.7.4...v0.8.0
[0.7.4]: https://github.com/fintoda/react-native-crypto-lib/compare/v0.5.4...v0.7.4
[0.5.4]: https://github.com/fintoda/react-native-crypto-lib/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/fintoda/react-native-crypto-lib/compare/v0.5.1...v0.5.3
[0.5.1]: https://github.com/fintoda/react-native-crypto-lib/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/fintoda/react-native-crypto-lib/releases/tag/v0.5.0

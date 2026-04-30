# CLAUDE.md

## Project overview

`@fintoda/react-native-crypto-lib` — cryptography library for React Native.
C++ Turbo Module (JSI) over vendored trezor-crypto. Zero-copy ArrayBuffer
API. Most primitives are synchronous; long-running ones (PBKDF2,
`bip39.toSeed`, `slip39.{generate,generateGroups,combine}`, every
`secureKV.*` and `biometric.*` call) are Promise-returning and run on
worker threads via `makePromiseAsync` (`cpp/Common.h`). Each async
domain also exposes a `*Sync` escape hatch.

## Tooling

- **Node** >= v24.13.0 (see `.nvmrc`)
- **Yarn** 4.11.0 (Berry, checked in at `.yarn/releases/`)
- **Turbo** for build caching (`turbo.json`)
- **react-native-builder-bob** for TS build + codegen
- **Lefthook** for git hooks (pre-commit: eslint + typecheck, commit-msg: commitlint)

## Architecture

Every crypto domain follows the same pattern:

1. **C++ module** (`cpp/<Domain>.cpp`) — implements JSI thunks, registers into `MethodMap`
2. **Registration** — function declared in `cpp/Common.h`, called from `cpp/ReactNativeCryptoLibImpl.cpp`
3. **TypeScript native wrapper** (`src/<domain>.native.tsx`) — imports `{ raw, toArrayBuffer }` from `src/buffer.tsx`, wraps ArrayBuffer ↔ Uint8Array
4. **TypeScript fallback** (`src/<domain>.tsx`) — same API shape, every method throws "not supported on non-native platforms"
5. **Barrel export** in `src/index.tsx`
6. **Build system** — add vendor `.c` sources to BOTH `android/CMakeLists.txt` AND `ReactNativeCryptoLib.podspec` (keep lists in sync!), add `cpp/<Domain>.cpp` to `add_library` in CMakeLists.txt (podspec globs `cpp/**/*.cpp` automatically)

### Key conventions

- `src/buffer.tsx` exports `raw` (the RawSpec cast) and `toArrayBuffer` — all `.native.tsx` files import from there, no duplication
- `RawSpec` in `src/NativeReactNativeCryptoLib.ts` types all native methods manually — RN codegen doesn't support ArrayBuffer in TurboModule specs
- C++ methods use `requireArrayBufferAt`, `requireIntAt`, `requireStringAt`, `requireBoolAt` from `Common.h` for input validation
- All sensitive C++ buffers MUST be zeroed with `memzero()` on every code path (including error throws)
- Vendor source lists are explicit, not globbed — intentional for build-failure-on-missing-dep

### JSI data passing patterns

- Binary data: `ArrayBuffer` (zero-copy via `toArrayBuffer()`)
- Strings: `jsi::String` / `std::string`
- Arrays of strings across JSI: join with `\n` delimiter on TS side, split in C++ (mnemonics in slip39_combine)
- Packed structs across JSI: `ArrayBuffer` of uint8 pairs (groups in slip39_generate_groups)
- Return arrays/nested arrays from C++: construct `jsi::Array` directly

### Async dispatch (heavy ops + secureKV)

- Three phases: Phase 1 validates JSI args on the JS thread (synchronous
  `jsi::JSError` throws from validation surface as Promise rejections via
  `safeAsyncThunk`), Phase 2 runs the actual work on a worker via
  `makePromiseAsync<BgResult>` (no `jsi::Runtime` access — capture inputs
  by value), Phase 3 wraps the result back into a `jsi::Value` on the JS
  thread.
- Worker-thread helpers throw `std::runtime_error("reason")`; callers
  prepend `"<op>: "` so error messages match the sync wrappers' format.
- The sync and async variants of an operation share the same C++ helper
  function (e.g. `doSlip39Generate`) so behaviour is identical between
  the two paths.
- TS API convention: heavy ops expose the async variant under the
  unsuffixed name (`bip39.toSeed`, `slip39.generate`) and the sync
  variant under the `*Sync` suffix.

### Vendor (trezor-crypto)

Vendored at `vendor/trezor-crypto/crypto/`. Only explicitly listed sources are compiled — the directory contains many more files (cardano, monero, nem, chacha20, noise, etc.) that are intentionally excluded. To use a new vendor module: add its `.c` file to both build manifests and `#include` its header with `extern "C" {}`.

## Adding a new crypto domain (checklist)

1. Create `cpp/<Domain>.cpp` with `namespace facebook::react::cryptolib`
2. Implement JSI thunks: `jsi::Value invoke_<method>(jsi::Runtime&, TurboModule&, const jsi::Value*, size_t)`.
   For sync ops, the body validates args and returns a `jsi::Value`
   directly. For async ops, wrap the body in `safeAsyncThunk(rt, [&]{ ... })`
   and return `makePromiseAsync<BgResult>(rt, "<op>", bgWork, finishWork)` —
   factor the heavy work into a helper that takes only POD/STL inputs so
   sync and async paths can share it.
3. Add `void register<Domain>Methods(MethodMap& map)` registration function
4. Declare it in `cpp/Common.h`
5. Call it in `cpp/ReactNativeCryptoLibImpl.cpp` constructor
6. Add any new vendor `.c` to `android/CMakeLists.txt` (TREZOR_CRYPTO_SOURCES) AND `ReactNativeCryptoLib.podspec` (trezor_crypto_sources)
7. Add `cpp/<Domain>.cpp` to `add_library` in CMakeLists.txt
8. Add method signatures to `RawSpec` in `src/NativeReactNativeCryptoLib.ts`
   (Promise-returning for async thunks)
9. Create `src/<domain>.native.tsx` (import from `src/buffer.tsx`).
   Async ops use `wrapNativeAsync`; sync ops use `wrapNative`.
10. Create `src/<domain>.tsx` (fallback) — match async/sync return types
11. Export from `src/index.tsx`
12. Run `yarn prepare` to rebuild TS + codegen
13. Add test vectors to `example/src/testVectors.ts`
14. Build and test on iOS and Android

## Commands

```sh
yarn prepare          # Build TS + codegen (run after ANY src/ changes for lib output)
yarn typecheck        # TypeScript type check
yarn lint             # ESLint (0 errors, 0 warnings expected)
yarn lint --fix       # Auto-fix formatting
yarn test             # Jest unit tests (src/__tests__/)
```

### Building example app

```sh
# iOS (simulator name depends on installed Xcode/simulators)
cd example/ios && pod install
xcodebuild -workspace ReactNativeCryptoLibExample.xcworkspace \
  -scheme ReactNativeCryptoLibExample -configuration Debug \
  -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build

# Android
yarn turbo run build:android
```

### Runtime tests

`example/src/testVectors.ts` contains 150+ crypto test vectors from authoritative sources (NIST FIPS, RFCs, BIP-340). These run on-device in the example app — NOT executed by `yarn test`. Test vectors use `check()`, `hexCheck()`, and `throws()` helpers.

## Code style

- Conventional commits enforced by commitlint (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`)
- No Co-Authored-By lines in commits
- ESLint with prettier; `no-bitwise` rule is off (legitimate in crypto)
- C++20 standard, no extensions
- Fallback `.tsx` files must match native `.native.tsx` API surface exactly (same parameter names, same defaults)

## Security rules

- Every C++ function that touches secrets (private keys, seeds, master secrets, PBKDF2 output, Shamir shares, ECDH shared secrets) MUST `memzero()` all intermediate buffers before returning or throwing
- AES: constant-time PKCS#7 padding validation (no early exit), zero plaintext buffer on GCM auth failure
- Feistel (SLIP-39): zero L, R, key, salt, newR/newL after every round iteration
- ECDSA/Schnorr: zero all scalar temporaries (`d`, `k`, `probe`, `t`)
- Input validation at JSI boundary — never trust buffer sizes from JS
- Compiler hardening: `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2` on both platforms
- `-Wno-deprecated-volatile` suppresses C++20 warnings from trezor-crypto's C-style volatile usage

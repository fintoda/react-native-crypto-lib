# @fintoda/react-native-crypto-lib

A comprehensive cryptography library for React Native, backed by a vendored
[trezor-crypto](https://github.com/trezor/trezor-firmware/tree/main/crypto)
C core and exposed as a synchronous JSI / Turbo Module. Zero-copy
`ArrayBuffer` transfers, no base64 bridge hops, no promises for operations
that don't need them.

- **Hashes**: SHA-1/256/384/512, SHA3-256/512, Keccak-256/512, RIPEMD-160,
  BLAKE-256, BLAKE2b, BLAKE2s, Groestl-512, SHA-256d, Hash160.
- **MAC / KDF**: HMAC-SHA256/512, PBKDF2-SHA256/512, HKDF-SHA256/512.
- **RNG**: cryptographically secure random bytes backed by
  the OS CSPRNG (`arc4random_buf` on iOS / Android NDK).
- **ECDSA** on secp256k1 and nist256p1: deterministic RFC 6979 signing,
  low-S normalisation, public-key recovery, ECDH, DER encode/decode.
- **Schnorr / BIP-340**: sign, verify, x-only keys, taproot tweak.
- **Ed25519** (RFC 8032) and **X25519** key exchange.
- **AES-256**: CBC (PKCS#7 or no padding), CTR, GCM with AAD.
- **BIP-39** mnemonics and **BIP-32 / SLIP-10** HD derivation on
  secp256k1, nist256p1, and ed25519.
- **SLIP-39** Shamir secret sharing: split a master secret into
  threshold-of-N mnemonic shares (single or multi-group), recover from
  shares, passphrase encryption, RS1024 checksum validation.
- **`tiny-secp256k1@2.x` adapter** so `bitcoinjs-lib`, `bip32`, `ecpair`
  work out of the box without a WASM build.
- **WebCrypto `getRandomValues` polyfill** for packages that expect a
  browser-style `crypto` global (`@noble/*`, `uuid`, `ethers`, …).

## Requirements

- React Native with the **new architecture** enabled — the library is
  implemented as a C++ Turbo Module and does not register under the old
  bridge.
- **Hermes** JS engine.
- Developed and tested against **React Native 0.85**. Earlier versions
  down to 0.76 (the first release with stable C++ Turbo Module codegen)
  may work but are not tested; older than 0.76 definitely will not.
- iOS and Android minimums are whatever the host React Native version
  requires — this library adds no extra floor on top.

## Installation

```sh
yarn add @fintoda/react-native-crypto-lib
cd ios && pod install
```

No extra Metro / Babel configuration needed.

## Quick start

```ts
import {
  hash,
  ecdsa,
  bip39,
  bip32,
  installCryptoPolyfill,
} from '@fintoda/react-native-crypto-lib';

// Install the WebCrypto polyfill once, at app startup, so any library
// that pokes at globalThis.crypto.getRandomValues keeps working.
installCryptoPolyfill();

// BIP-39 → BIP-32 → ECDSA signing:
const mnemonic = bip39.generate(128);
const seed = bip39.toSeed(mnemonic, '');
const root = bip32.fromSeed(seed, 'secp256k1');
const leaf = bip32.derive(root, "m/44'/0'/0'/0/0");

const msg = hash.sha256(new TextEncoder().encode('hello'));
const { signature, recId } = ecdsa.sign(leaf.privateKey!, msg);
const ok = ecdsa.verify(leaf.publicKey, signature, msg);
```

All `Uint8Array` inputs are consumed zero-copy when they cover the whole
underlying buffer; otherwise the wrapper makes one defensive slice.

## Table of contents

- [hash](#hash) — one-shot digests
- [mac](#mac) — HMAC
- [kdf](#kdf) — PBKDF2 / HKDF
- [rng](#rng) — secure random
- [ecdsa](#ecdsa) — secp256k1 / nist256p1
- [schnorr](#schnorr) — BIP-340
- [ed25519 / x25519](#ed25519--x25519)
- [ecc](#ecc) — low-level secp256k1 primitives
- [tinySecp256k1](#tinysecp256k1) — bitcoinjs adapter
- [aes](#aes) — AES-256 CBC / CTR / GCM
- [bip39](#bip39) — mnemonics
- [bip32](#bip32) — HD derivation (SLIP-10)
- [slip39](#slip39) — Shamir secret sharing
- [secureKV](#securekv) — hardware-backed key/value storage
- [webcrypto](#webcrypto) — getRandomValues polyfill
- [Compatibility notes](#compatibility-notes)

---

## hash

One-shot digest functions. Each returns a fresh `Uint8Array`.

```ts
import { hash } from '@fintoda/react-native-crypto-lib';
```

| function | output bytes | notes |
|---|---|---|
| `hash.sha1(data)` | 20 | legacy; not recommended |
| `hash.sha256(data)` | 32 | |
| `hash.sha384(data)` | 48 | |
| `hash.sha512(data)` | 64 | |
| `hash.sha3_256(data)` | 32 | NIST SHA3 |
| `hash.sha3_512(data)` | 64 | NIST SHA3 |
| `hash.keccak_256(data)` | 32 | pre-NIST Keccak (Ethereum) |
| `hash.keccak_512(data)` | 64 | pre-NIST Keccak |
| `hash.ripemd160(data)` | 20 | |
| `hash.blake256(data)` | 32 | |
| `hash.blake2b(data)` | 64 | |
| `hash.blake2s(data)` | 32 | |
| `hash.groestl512(data)` | 64 | |
| `hash.sha256d(data)` | 32 | SHA256(SHA256(x)), Bitcoin |
| `hash.hash160(data)` | 20 | RIPEMD160(SHA256(x)) |

All take a `Uint8Array` and return a `Uint8Array`.

## mac

```ts
import { mac } from '@fintoda/react-native-crypto-lib';
```

| function | output |
|---|---|
| `mac.hmac_sha256(key, msg)` | 32 bytes |
| `mac.hmac_sha512(key, msg)` | 64 bytes |

## kdf

```ts
import { kdf } from '@fintoda/react-native-crypto-lib';
```

- `kdf.pbkdf2_sha256(password, salt, iterations, length)` → `Uint8Array(length)`
- `kdf.pbkdf2_sha512(password, salt, iterations, length)` → `Uint8Array(length)`
- `kdf.hkdf_sha256(ikm, salt, info, length)` → `Uint8Array(length)`
- `kdf.hkdf_sha512(ikm, salt, info, length)` → `Uint8Array(length)`

`length` is capped at `255 * hashLen` per RFC 5869 / the PBKDF2 reference
impl. `iterations` is capped at 10,000,000 as a sanity check.

## rng

```ts
import { rng } from '@fintoda/react-native-crypto-lib';
```

- `rng.bytes(count)` → `Uint8Array` — cryptographically secure random
  bytes. `count` is capped at 1 MiB per call.
- `rng.uint32()` → `number` — unsigned 32-bit integer.
- `rng.uniform(max)` → `number` — uniform random integer in `[0, max)`,
  no modulo bias. `max` must be a positive integer.

## ecdsa

```ts
import { ecdsa, type Curve } from '@fintoda/react-native-crypto-lib';
```

`Curve` is `'secp256k1' | 'nist256p1'`. All functions default to
`secp256k1` when the argument is omitted.

- `ecdsa.randomPrivate(curve?)` → `Uint8Array(32)` — uniform in `[1, n-1]`.
- `ecdsa.validatePrivate(priv, curve?)` → `boolean`.
- `ecdsa.getPublic(priv, compact = true, curve?)` →
  `Uint8Array` (33 bytes compressed or 65 bytes uncompressed).
- `ecdsa.readPublic(pub, compact = true, curve?)` → re-serialises a
  public key into the requested form. Validates it on the way.
- `ecdsa.validatePublic(pub, curve?)` → `boolean`.
- `ecdsa.sign(priv, digest, curve?)` →
  `{ signature: Uint8Array(64), recId: 0 | 1 | 2 | 3 }`.
  RFC 6979 deterministic, output is low-S.
- `ecdsa.verify(pub, sig64, digest, curve?)` → `boolean`. Accepts both
  low-S and high-S signatures; use `tinySecp256k1.verify(..., true)` for
  strict BIP-62 low-S enforcement.
- `ecdsa.recover(sig64, digest, recId, curve?)` → `Uint8Array(65)`
  uncompressed.
- `ecdsa.ecdh(priv, pub, curve?)` → `Uint8Array(33)` compressed shared
  point. If you want the legacy `SHA256(x)` behaviour, do
  `hash.sha256(ecdh(priv, pub).slice(1))`.
- `ecdsa.sigToDer(sig64)` / `ecdsa.sigFromDer(der)`.

## schnorr

BIP-340 Schnorr on secp256k1, x-only keys.

```ts
import { schnorr } from '@fintoda/react-native-crypto-lib';
```

- `schnorr.getPublic(priv)` → `Uint8Array(32)` x-only pubkey.
- `schnorr.verifyPublic(pub32)` → `boolean`.
- `schnorr.sign(priv, digest, aux?)` → `Uint8Array(64)`. `aux` is the
  optional 32-byte auxiliary randomness; when omitted, 32 zero bytes are
  used (spec-compliant).
- `schnorr.verify(pub32, sig64, digest)` → `boolean`.
- `schnorr.tweakPublic(pub32, merkleRoot?)` →
  `{ pub: Uint8Array(32), parity: 0 | 1 }`. Implements the BIP-341
  TapTweak: if `merkleRoot` is omitted or zero-length, the key-spend
  tweak `H_TapTweak(pub)` is used.
- `schnorr.tweakPrivate(priv, merkleRoot?)` → `Uint8Array(32)`.

## ed25519 / x25519

Vanilla Ed25519 (RFC 8032, SHA-512) and X25519 ECDH.

```ts
import { ed25519, x25519 } from '@fintoda/react-native-crypto-lib';
```

- `ed25519.getPublic(priv32)` → `Uint8Array(32)` pubkey from a 32-byte seed.
- `ed25519.sign(priv32, msg)` → `Uint8Array(64)` signature over the raw
  message (Ed25519 hashes the message internally).
- `ed25519.verify(pub32, sig64, msg)` → `boolean`.
- `x25519.getPublic(priv32)` → `Uint8Array(32)`.
- `x25519.scalarmult(priv32, pub32)` → `Uint8Array(32)` shared secret.

## ecc

Low-level secp256k1 point / scalar primitives used by the
`tinySecp256k1` adapter but also exported directly. All return `null` on
operations that collapse to the point at infinity / an out-of-range
scalar; malformed inputs throw.

```ts
import { ecc } from '@fintoda/react-native-crypto-lib';
```

- `ecc.pointAdd(a, b, compressed = true)` → `Uint8Array | null`.
- `ecc.pointAddScalar(p, tweak, compressed = true)` → `Uint8Array | null`.
- `ecc.pointMultiply(p, tweak, compressed = true)` → `Uint8Array | null`.
- `ecc.privateAdd(d, tweak)` → `Uint8Array | null`.
- `ecc.privateSub(d, tweak)` → `Uint8Array | null`.
- `ecc.privateNegate(d)` → `Uint8Array`.
- `ecc.xOnlyPointAddTweak(p32, tweak32)` →
  `{ parity: 0 | 1, xOnlyPubkey: Uint8Array(32) } | null`. This is the
  **bare** scalar tweak, not the BIP-341 TapTweak — use
  `schnorr.tweakPublic` for the latter.

## tinySecp256k1

Drop-in implementation of the `TinySecp256k1Interface` consumed by
`bitcoinjs-lib`, `ecpair` and `bip32`. Wire it up wherever those packages
expect an `eccLib`:

```ts
import { tinySecp256k1 } from '@fintoda/react-native-crypto-lib';
import BIP32Factory from 'bip32';
import ECPairFactory from 'ecpair';

const bip32Factory = BIP32Factory(tinySecp256k1);
const ECPair = ECPairFactory(tinySecp256k1);
```

Full method list (`tiny-secp256k1@2.x`):

- Validation: `isPoint`, `isPointCompressed`, `isXOnlyPoint`, `isPrivate`.
- Point ops: `pointAdd`, `pointAddScalar`, `pointMultiply`,
  `pointFromScalar`, `pointCompress`.
- X-only: `xOnlyPointFromScalar`, `xOnlyPointFromPoint`,
  `xOnlyPointAddTweak`, `xOnlyPointAddTweakCheck`.
- Scalars: `privateAdd`, `privateSub`, `privateNegate`.
- ECDSA: `sign(h, d, e?)`, `signRecoverable(h, d, e?)`,
  `verify(h, Q, sig, strict?)`, `recover(h, sig, recId, compressed?)`.
- Schnorr: `signSchnorr(h, d, e?)`, `verifySchnorr(h, Q, sig)`.

Notes:

- The optional `e` / extra-entropy argument on ECDSA/Schnorr is ignored
  for ECDSA (we're RFC 6979 deterministic) and forwarded as `aux_rand`
  for Schnorr.
- `verify(..., strict = true)` enforces BIP-62 low-S; the default
  (`false`) accepts high-S, matching tiny-secp256k1.

## aes

AES-256 with caller-provided IV / nonce. Key is always 32 bytes.

```ts
import { aes, type CbcPadding } from '@fintoda/react-native-crypto-lib';
```

### CBC

- `aes.cbc.encrypt(key32, iv16, data, padding = 'pkcs7')` → ciphertext.
- `aes.cbc.decrypt(key32, iv16, data, padding = 'pkcs7')` → plaintext.
  Throws on invalid PKCS#7 padding.
- `padding` is `'pkcs7' | 'none'`. With `'none'` the input length must
  be a multiple of 16.

### CTR

- `aes.ctr.crypt(key32, iv16, data)` → same-length buffer. Symmetric:
  the same call encrypts and decrypts.

### GCM

- `aes.gcm.encrypt(key32, nonce, plaintext, aad?)` →
  `Uint8Array(plaintext.length + 16)`. The trailing 16 bytes are the
  authentication tag (WebCrypto / `node:crypto` layout).
- `aes.gcm.decrypt(key32, nonce, sealed, aad?)` → plaintext.
  Throws `aes_256_gcm_decrypt: authentication failed` if the tag does
  not match.
- `nonce` length is validated as non-empty; 12 bytes is recommended.

## bip39

```ts
import { bip39, type Bip39Strength } from '@fintoda/react-native-crypto-lib';
```

- `bip39.generate(strength = 128)` → `string`. `strength` is one of
  `128 | 160 | 192 | 224 | 256` (12 / 15 / 18 / 21 / 24 words).
- `bip39.fromEntropy(entropy)` → `string`. Entropy length must be
  16, 20, 24, 28 or 32 bytes.
- `bip39.validate(mnemonic)` → `boolean`. Verifies the checksum and
  wordlist membership.
- `bip39.toSeed(mnemonic, passphrase = '')` → `Uint8Array(64)`.
  PBKDF2-HMAC-SHA512, 2048 rounds, salt = `"mnemonic" + passphrase`.

## bip32

BIP-32 / SLIP-10 HD key derivation on three curves. The JS `HDNode`
carries a 108-byte opaque `raw` blob that all native derive calls take
as input — one JSI hop per full path:

```ts
import { bip32, type Bip32Curve, type HDNode } from '@fintoda/react-native-crypto-lib';
```

- `bip32.fromSeed(seed, curve = 'secp256k1')` → `HDNode`. `curve` is
  `'secp256k1' | 'nist256p1' | 'ed25519'`.
- `bip32.derive(node, path)` → `HDNode`. `path` is either a BIP-32
  string (`"m/44'/0'/0'/0/0"`) or a numeric index array (hardened
  indices must have the `0x80000000` bit set).
- `bip32.derivePublic(node, path)` → `HDNode` — public-only derivation;
  throws on hardened indices and on ed25519 (SLIP-10 public derivation
  is undefined for ed25519).
- `bip32.neuter(node)` → `HDNode` — returns a copy with the private key
  stripped.
- `bip32.serialize(node, version, isPrivate)` → xprv / xpub string.
  Typical Bitcoin mainnet versions: `0x0488ADE4` (xprv), `0x0488B21E`
  (xpub).
- `bip32.deserialize(str, version, curve, isPrivate)` → `HDNode`.
- `bip32.fingerprint(node)` → `number` — this node's own fingerprint.
- `bip32.HARDENED_OFFSET` = `0x80000000`.

`HDNode` shape:

```ts
type HDNode = {
  curve: Bip32Curve;
  depth: number;
  parentFingerprint: number;
  childNumber: number;
  chainCode: Uint8Array;   // 32 bytes
  privateKey: Uint8Array | null; // 32 bytes or null when neutered
  publicKey: Uint8Array;   // 33 bytes, compressed (or SLIP-10 ed25519 pub)
  raw: Uint8Array;         // 108-byte opaque blob passed back to derive()
};
```

### SLIP-10 notes

- On `ed25519`, every child must be hardened. Non-hardened derivation
  throws.
- On `ed25519`, the 33-byte `publicKey` has a leading `0x00` tag byte
  followed by 32 bytes of the Ed25519 public key — the same convention
  trezor-crypto uses. You typically pass `privateKey` into
  `ed25519.sign` rather than using the 33-byte form directly.

## slip39

[SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
Shamir secret sharing — split a master secret into mnemonic shares that
can be distributed for safekeeping.

```ts
import { slip39, type Slip39Group } from '@fintoda/react-native-crypto-lib';
```

### Single group (threshold-of-N)

```ts
const secret = new Uint8Array(16); // 16–32 bytes, even length
// Split into 5 shares, any 3 recover the secret
const shares: string[] = slip39.generate(secret, 'passphrase', 3, 5);

// Recover from any 3 shares
const recovered: Uint8Array = slip39.combine(
  [shares[0], shares[2], shares[4]],
  'passphrase',
);
```

### Multi-group

```ts
// 2-of-3 groups; each group has its own member threshold
const groups: string[][] = slip39.generateGroups(secret, 'passphrase', 2, [
  { threshold: 2, count: 3 }, // group 0: 2-of-3
  { threshold: 3, count: 5 }, // group 1: 3-of-5
  { threshold: 1, count: 1 }, // group 2: 1-of-1 (backup)
]);

// Recover with shares from 2 groups
const recovered = slip39.combine(
  [...groups[0].slice(0, 2), groups[2][0]],
  'passphrase',
);
```

### API

- `slip39.generate(masterSecret, passphrase?, threshold, shareCount, iterationExponent? = 1)` → `string[]`.
  Returns `shareCount` SLIP-39 mnemonics. `masterSecret` must be 16–32
  bytes (even). Passphrase encrypts the secret via a 4-round Feistel
  cipher with PBKDF2-HMAC-SHA256 (10 000 × 2^exp iterations per round).
- `slip39.generateGroups(masterSecret, passphrase?, groupThreshold, groups, iterationExponent? = 1)` → `string[][]`.
  Two-level Shamir: `groups` is an array of `{ threshold, count }`.
- `slip39.combine(mnemonics, passphrase?)` → `Uint8Array`.
  Recover the master secret from enough shares (single or multi-group).
- `slip39.validateMnemonic(mnemonic)` → `boolean`.
  Wordlist + RS1024 checksum validation.

## secureKV

Hardware-backed key/value storage. Synchronous `Uint8Array` API matching
the rest of the library — no Promises, no string encoding hop, secrets
stay as bytes from the Keychain / Keystore boundary up to your hands.

The motivation is to keep private material out of the JS heap as much as
possible. Generating or importing a key still touches JS once, but storing
and reading it back through `secureKV` does not stringify, base64, or
otherwise transit the bridge as text. A future native-only sign API
(`secureKV.signEcdsa(alias, digest)`) will close the loop so the secret
never re-enters JS for routine signing.

```ts
import {
  secureKV,
  SecureKVUnavailableError,
  type AccessControl,
} from '@fintoda/react-native-crypto-lib';
```

### API

- `secureKV.set(key, value, accessControl? = 'none')` — store
  `value: Uint8Array` under `key`. Silently overwrites an existing
  value. `accessControl` is currently restricted to `'none'`; it's
  reserved for future biometric / user-presence gating without
  breaking call sites.
- `secureKV.get(key)` → `Uint8Array | null`. Returns `null` if the key
  was never set or has been deleted. Throws `SecureKVUnavailableError`
  if the OS-managed master key has been invalidated (factory reset,
  some screen-lock changes on Android).
- `secureKV.has(key)` → `boolean`.
- `secureKV.delete(key)` — idempotent; deleting a missing key is a no-op.
- `secureKV.list()` → `string[]` of all keys currently stored. Skips
  individual blobs whose authentication tag fails (orphans of a prior
  key generation), but throws `SecureKVUnavailableError` if the master
  key itself is gone — matching `get()`'s behaviour so a wiped store
  doesn't silently look like an empty one.
- `secureKV.clear()` — wipe all keys belonging to this app.
- `secureKV.isHardwareBacked()` → `boolean`. Informational. iOS always
  reports `true` (Keychain is always Secure Enclave-protected with
  `*ThisDeviceOnly` accessibility); Android reports whether the master
  key landed in TEE / StrongBox vs. software keystore.

`key` must match `[A-Za-z0-9._-]` (≤128 chars). `value` must be ≤64 KiB.
The store is per-app — two apps using this library on the same device
have independent namespaces. Single-process only on Android: don't enable
multi-process for the host app if you rely on `secureKV`.

```ts
import { rng, secureKV } from '@fintoda/react-native-crypto-lib';

// One-time provision
const seed = rng.bytes(32);
secureKV.set('wallet.seed', seed);
seed.fill(0);

// Later
const restored = secureKV.get('wallet.seed');
if (!restored) throw new Error('seed missing');
```

### How it works

The implementation is intentionally small and auditable. Both backends
share the same C++ JSI thunk layer (`cpp/SecureKV.cpp`), which validates
the key charset / length and the 64 KiB value cap before forwarding to a
platform `SecureKVBackend`.

#### iOS — Keychain

Each value becomes one `kSecClassGenericPassword` item with these
attributes:

| attribute | value |
|---|---|
| `kSecAttrService` | `"<bundleId>.cryptolib.kv"` |
| `kSecAttrAccount` | the user-supplied key name |
| `kSecAttrAccessible` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| `kSecAttrSynchronizable` | unset (default `false` — never iCloud-synced) |
| `kSecAttrAccessGroup` | unset (host app's default group only) |

The accessibility class chosen is the strictest one that's still usable
for UI flows: the item is decryptable only while the device is unlocked
and *only on the device that wrote it* — restoring the encrypted backup
to a new phone leaves the item unreadable. Background tasks running
while the screen is locked cannot read; if you need that, switch to
`AfterFirstUnlockThisDeviceOnly` in a fork (we picked the stricter
default deliberately).

`set` is `SecItemDelete` then `SecItemAdd` — overwrite-by-recreate so
that an item written under an older accessibility attribute (e.g. before
the library upgraded its default) doesn't silently retain it via
`SecItemUpdate`.

#### Android — AndroidKeystore + sealed blobs

There is no Keychain-equivalent KV store on Android, so the library
brings its own thin one. A single AES-256-GCM master key lives in
AndroidKeystore under alias `cryptolib.kv.master.<applicationId>`,
generated lazily on first use with:

```kotlin
KeyGenParameterSpec.Builder(alias, ENCRYPT or DECRYPT)
  .setBlockModes(BLOCK_MODE_GCM)
  .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
  .setKeySize(256)
  .setRandomizedEncryptionRequired(true)
  .build()
```

`setRandomizedEncryptionRequired(true)` means the platform supplies a
fresh random IV per `Cipher.init(ENCRYPT_MODE)` and rejects any attempt
by us to provide one — the only way to use this key is the safe one.

Each value is sealed independently and stored as a single file at
`<filesDir>/secure_kv/<sha256(keyName)>.bin`:

```
+-----------+------------------------------+----------+
| IV (12 B) | AES-GCM(plaintext)           | tag (16) |
+-----------+------------------------------+----------+

plaintext =
  +--------------+---------------------+----------------+
  | keyLen (4 B  | UTF-8 keyName       | value bytes    |
  | big-endian)  | (keyLen bytes)      |                |
  +--------------+---------------------+----------------+
```

Embedding the key name **inside** the encrypted plaintext lets `list()`
recover original (case-preserving) names by decrypting each blob,
without keeping a sidecar index file that would have to be kept atomic
with the store. `get()` additionally verifies that the recovered key
name matches the requested one as defence-in-depth on top of GCM
authentication.

Writes go through `<file>.tmp` followed by `renameTo`, so a crash
mid-write leaves either the previous blob or the new one — never a
half-written file. `set`, `delete`, and `clear` run under the same JVM
monitor that guards master-key creation so concurrent writers (in the
unlikely event there are any) can't interleave.

When the master key has been invalidated by the OS — typically after
factory reset, or on some OEM ROMs after the user removes the device
screen lock — `Cipher.init` throws `KeyPermanentlyInvalidatedException`
or `UnrecoverableKeyException`. The library catches these specifically
and surfaces them as `SecureKVUnavailableError`. Single-blob auth
failures (`AEADBadTagException`, `BadPaddingException`) are treated as
orphans: `get` rejects them as unavailable, while `list` skips just the
bad one and continues — a wiped store still surfaces as a single
unavailable error rather than as a misleading empty list.

#### Where hardware backing actually applies

`isHardwareBacked()` reports the OS's view of where the master key
material physically lives:

| device class | typical backing |
|---|---|
| Pixel 3+ / Samsung S20+ with StrongBox | dedicated security chip (StrongBox) |
| most Android ≥ 7 | TEE (Trusty / Qualcomm SEE) — separate execution environment in the SoC |
| old / emulator / no TEE | software keystore, encrypted with a system master key on disk |

iOS always reports `true`: every Keychain item with a `*ThisDeviceOnly`
accessibility class is encrypted using a key derived from the Secure
Enclave UID, which never leaves silicon.

The library does **not** refuse to operate on software-keystore devices
— that would break emulators and old hardware unnecessarily. Inspect
`isHardwareBacked()` if you want to make a product decision (e.g. force
the user to set up a screen lock first), but the library itself treats
the answer as informational.

### Durability — read this before storing anything you cannot recover

These properties are **intentional** for wallet / seed-class secrets and
inherent to the underlying OS APIs. Do not store anything here that you
need to survive these events:

- **Uninstalling the app** wipes all stored values (file directory and
  Keystore alias / Keychain items are removed by the OS).
- **Factory reset** invalidates the master key. Old blobs become
  permanently undecryptable.
- **Restoring to a new device** does not migrate the store. Both
  platforms scope our items to the original device's hardware.
- **Removing or replacing the device passcode / screen lock** can
  invalidate the AndroidKeystore master key on some OEM ROMs,
  surfacing as `SecureKVUnavailableError` on the next `get()`.

When a backend reports the master key is no longer usable,
`secureKV.get()` (and `list()`) throws `SecureKVUnavailableError`
(`extends CryptoError`). Callers should catch this and re-derive their
secrets from a recovery source rather than retry blindly.

### Excluding from Auto Backup (Android)

Android's Auto Backup will, by default, copy app files to Google Drive
in a way that breaks our model: blobs go to the cloud but the master
key cannot leave the device, so restored data is unreadable. To prevent
the silent leak, opt the host app's manifest into the bundled rules:

```xml
<!-- android/app/src/main/AndroidManifest.xml -->
<application
  ...
  android:dataExtractionRules="@xml/secure_kv_data_extraction_rules"
  android:fullBackupContent="@xml/secure_kv_full_backup_content">
  ...
</application>
```

The XML resources are shipped by the library; you only need to point at
them. The library does **not** apply these settings via manifest merge,
to avoid stomping on backup rules the host app may already have.

### What it does not protect against

- **A rooted / jailbroken device with active malware.** The OS will
  happily decrypt for any process running as your app's UID. Hardware
  protection prevents extraction of the master key, not its use.
- **A future biometric / user-presence requirement.** Not in this
  version — `set` / `get` proceed without prompting. The
  `accessControl` parameter in the API is reserved for adding
  biometric-gated reads later without breaking callers.

## webcrypto

React Native / Hermes doesn't ship `globalThis.crypto.getRandomValues`,
which breaks any library that expects it (`@noble/*`, `uuid@v4`,
`ethers`, `bitcoinjs-lib` in some paths, `tweetnacl`, …). This module
plugs the hole:

```ts
import {
  getRandomValues,
  installCryptoPolyfill,
} from '@fintoda/react-native-crypto-lib';
```

- `installCryptoPolyfill()` → `boolean`. Assigns `getRandomValues` onto
  `globalThis.crypto` when it's missing. Idempotent — if a native
  `crypto.getRandomValues` already exists, it is not overwritten.
  Returns `true` if the polyfill was installed. Call this once at app
  startup, **before** importing any package that touches `crypto`.
- `getRandomValues(typedArray)` → the same typed array, filled with
  CSPRNG bytes. Throws a `QuotaExceededError`-equivalent on requests
  larger than 65,536 bytes (the WebCrypto cap). Accepts any integer
  typed array view (`Uint8Array`, `Int32Array`, …).

```ts
// index.js (very top of the app)
import { installCryptoPolyfill } from '@fintoda/react-native-crypto-lib';
installCryptoPolyfill();
```

## Compatibility notes

- All public APIs are **synchronous**. No promises, no awaits.
- Inputs are always `Uint8Array`; outputs are always fresh
  `Uint8Array` views. Nothing is base64 at the edge.
- Key formats match the wider ecosystem: compressed (33 B) and
  uncompressed (65 B) for secp256k1 / nist256p1, x-only (32 B) for
  BIP-340 Schnorr, raw 32-byte seeds for Ed25519 / X25519.
- The library is **not a complete drop-in** for earlier `CryptoLib`
  versions: function names are grouped into namespaces (`hash.*`,
  `ecdsa.*`, `bip32.*` …), signing is sync, HDNode fields use
  `Uint8Array` instead of base64 strings. A mechanical migration is
  straightforward.

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT. Vendored trezor-crypto is under its own MIT license; see
`vendor/trezor-crypto/crypto/LICENSE`.

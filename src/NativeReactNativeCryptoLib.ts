import { TurboModuleRegistry, type TurboModule } from 'react-native';

// The codegen Spec must be empty (well, almost) because RN 0.85 codegen
// does not support ArrayBuffer in TurboModule specs. All real native
// methods that take or return binary data are registered manually into
// methodMap_ from the C++ Impl constructor and typed via RawSpec below.
export interface Spec extends TurboModule {}

export interface RawSpec {
  hash_sha1(data: ArrayBuffer): ArrayBuffer;
  hash_sha256(data: ArrayBuffer): ArrayBuffer;
  hash_sha384(data: ArrayBuffer): ArrayBuffer;
  hash_sha512(data: ArrayBuffer): ArrayBuffer;
  hash_sha3_256(data: ArrayBuffer): ArrayBuffer;
  hash_sha3_512(data: ArrayBuffer): ArrayBuffer;
  hash_keccak_256(data: ArrayBuffer): ArrayBuffer;
  hash_keccak_512(data: ArrayBuffer): ArrayBuffer;
  hash_ripemd160(data: ArrayBuffer): ArrayBuffer;
  hash_blake256(data: ArrayBuffer): ArrayBuffer;
  hash_blake2b(data: ArrayBuffer): ArrayBuffer;
  hash_blake2s(data: ArrayBuffer): ArrayBuffer;
  hash_groestl512(data: ArrayBuffer): ArrayBuffer;
  hash_sha256d(data: ArrayBuffer): ArrayBuffer;
  hash_hash160(data: ArrayBuffer): ArrayBuffer;

  mac_hmac_sha256(key: ArrayBuffer, msg: ArrayBuffer): ArrayBuffer;
  mac_hmac_sha512(key: ArrayBuffer, msg: ArrayBuffer): ArrayBuffer;

  kdf_pbkdf2_sha256(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    length: number
  ): ArrayBuffer;
  kdf_pbkdf2_sha512(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    length: number
  ): ArrayBuffer;
  /** Async variants — derivation runs on a worker thread so the JS thread
   *  stays responsive. JS wrapper exposes these as `pbkdf2_sha{256,512}`,
   *  with sync paths kept under the `*Sync` suffix. */
  kdf_pbkdf2_sha256_async(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    length: number
  ): Promise<ArrayBuffer>;
  kdf_pbkdf2_sha512_async(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    length: number
  ): Promise<ArrayBuffer>;
  kdf_hkdf_sha256(
    ikm: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number
  ): ArrayBuffer;
  kdf_hkdf_sha512(
    ikm: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number
  ): ArrayBuffer;

  rng_bytes(count: number): ArrayBuffer;

  ecdsa_random_private(curve: string): ArrayBuffer;
  ecdsa_validate_private(curve: string, priv: ArrayBuffer): boolean;
  ecdsa_get_public(
    curve: string,
    priv: ArrayBuffer,
    compact: boolean
  ): ArrayBuffer;
  ecdsa_read_public(
    curve: string,
    pub: ArrayBuffer,
    compact: boolean
  ): ArrayBuffer;
  ecdsa_validate_public(curve: string, pub: ArrayBuffer): boolean;
  /** Returns 65 bytes: [recid, sig[0..64]] (signature is low-S). */
  ecdsa_sign(
    curve: string,
    priv: ArrayBuffer,
    digest: ArrayBuffer
  ): ArrayBuffer;
  ecdsa_verify(
    curve: string,
    pub: ArrayBuffer,
    sig: ArrayBuffer,
    digest: ArrayBuffer
  ): boolean;
  /** Returns 65-byte uncompressed public key. */
  ecdsa_recover(
    curve: string,
    sig: ArrayBuffer,
    digest: ArrayBuffer,
    recid: number
  ): ArrayBuffer;
  /** Returns 33-byte compressed shared public key. */
  ecdsa_ecdh(curve: string, priv: ArrayBuffer, pub: ArrayBuffer): ArrayBuffer;
  ecdsa_sig_to_der(sig: ArrayBuffer): ArrayBuffer;
  ecdsa_sig_from_der(der: ArrayBuffer): ArrayBuffer;

  /** BIP-340 Schnorr (secp256k1) — all keys are 32-byte x-only. */
  schnorr_get_public(priv: ArrayBuffer): ArrayBuffer;
  schnorr_verify_public(pub: ArrayBuffer): boolean;
  schnorr_sign(
    priv: ArrayBuffer,
    digest: ArrayBuffer,
    aux: ArrayBuffer | null
  ): ArrayBuffer;
  schnorr_verify(
    pub: ArrayBuffer,
    sig: ArrayBuffer,
    digest: ArrayBuffer
  ): boolean;
  /** Returns 33 bytes: tweaked_x(32) || parity(1). */
  schnorr_tweak_public(
    pub: ArrayBuffer,
    merkleRoot: ArrayBuffer | null
  ): ArrayBuffer;
  schnorr_tweak_private(
    priv: ArrayBuffer,
    merkleRoot: ArrayBuffer | null
  ): ArrayBuffer;

  /** Ed25519 (RFC 8032, SHA-512) on 32-byte seeds; signs raw messages. */
  ed25519_get_public(priv: ArrayBuffer): ArrayBuffer;
  ed25519_sign(priv: ArrayBuffer, msg: ArrayBuffer): ArrayBuffer;
  ed25519_verify(pub: ArrayBuffer, sig: ArrayBuffer, msg: ArrayBuffer): boolean;

  /** X25519 (curve25519) key-exchange. */
  x25519_get_public(priv: ArrayBuffer): ArrayBuffer;
  x25519_scalarmult(priv: ArrayBuffer, pub: ArrayBuffer): ArrayBuffer;

  /**
   * Low-level secp256k1 point / scalar primitives used by the
   * tiny-secp256k1 adapter. Empty ArrayBuffer return means "null"
   * (operation produced point at infinity / invalid scalar).
   */
  ecc_point_add(
    a: ArrayBuffer,
    b: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer;
  ecc_point_add_scalar(
    p: ArrayBuffer,
    tweak: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer;
  ecc_point_multiply(
    p: ArrayBuffer,
    tweak: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer;
  ecc_private_add(d: ArrayBuffer, tweak: ArrayBuffer): ArrayBuffer;
  ecc_private_sub(d: ArrayBuffer, tweak: ArrayBuffer): ArrayBuffer;
  ecc_private_negate(d: ArrayBuffer): ArrayBuffer;
  /** Returns 33 bytes: tweaked_x(32) || parity(1); empty on infinity. */
  ecc_xonly_point_add_tweak(p: ArrayBuffer, tweak: ArrayBuffer): ArrayBuffer;

  /**
   * AES-256. key is always 32 bytes; iv/nonce is caller-generated.
   * GCM encrypt returns ciphertext||tag(16), decrypt takes the same
   * layout. padding for CBC is "pkcs7" | "none".
   */
  aes_256_cbc_encrypt(
    key: ArrayBuffer,
    iv: ArrayBuffer,
    data: ArrayBuffer,
    padding: string
  ): ArrayBuffer;
  aes_256_cbc_decrypt(
    key: ArrayBuffer,
    iv: ArrayBuffer,
    data: ArrayBuffer,
    padding: string
  ): ArrayBuffer;
  aes_256_ctr_crypt(
    key: ArrayBuffer,
    iv: ArrayBuffer,
    data: ArrayBuffer
  ): ArrayBuffer;
  aes_256_gcm_encrypt(
    key: ArrayBuffer,
    nonce: ArrayBuffer,
    plaintext: ArrayBuffer,
    aad: ArrayBuffer | null
  ): ArrayBuffer;
  aes_256_gcm_decrypt(
    key: ArrayBuffer,
    nonce: ArrayBuffer,
    sealed: ArrayBuffer,
    aad: ArrayBuffer | null
  ): ArrayBuffer;

  /** BIP-39 mnemonic handling. strength must be 128/160/192/224/256. */
  bip39_generate(strength: number): string;
  bip39_from_entropy(entropy: ArrayBuffer): string;
  bip39_check(mnemonic: string): boolean;
  bip39_to_seed(mnemonic: string, passphrase: string): ArrayBuffer;
  /** Async — internal PBKDF2-HMAC-SHA512×2048 runs on a worker thread.
   *  JS API exposes this as `bip39.toSeed`. */
  bip39_to_seed_async(
    mnemonic: string,
    passphrase: string
  ): Promise<ArrayBuffer>;

  /**
   * BIP-32 / SLIP-10 HD key derivation. HDNode is serialized as a fixed
   * 108-byte binary blob: curve_tag(1) | has_private(1) | depth(1) |
   * parent_fp(4 BE) | child_num(4 BE) | chain_code(32) | private_key(32) |
   * public_key(33). Curve is "secp256k1" | "nist256p1" | "ed25519".
   */
  bip32_from_seed(seed: ArrayBuffer, curve: string): ArrayBuffer;
  /** path is N big-endian u32 indices packed as 4*N bytes. */
  bip32_derive(node: ArrayBuffer, path: ArrayBuffer): ArrayBuffer;
  bip32_derive_public(node: ArrayBuffer, path: ArrayBuffer): ArrayBuffer;
  bip32_serialize(
    node: ArrayBuffer,
    version: number,
    isPrivate: boolean
  ): string;
  bip32_deserialize(
    str: string,
    version: number,
    curve: string,
    isPrivate: boolean
  ): ArrayBuffer;
  bip32_fingerprint(node: ArrayBuffer): number;

  /**
   * SLIP-39 Shamir Secret Sharing.
   * Single-group: split master secret into threshold-of-shareCount shares.
   *
   * `*_async` variants run PBKDF2+Feistel on a worker thread; JS API
   * exposes them as the unsuffixed `slip39.{generate,generateGroups,combine}`,
   * with the sync paths under the `*Sync` suffix.
   */
  slip39_generate(
    masterSecret: ArrayBuffer,
    passphrase: string,
    threshold: number,
    shareCount: number,
    iterationExponent: number
  ): string[];
  slip39_generate_async(
    masterSecret: ArrayBuffer,
    passphrase: string,
    threshold: number,
    shareCount: number,
    iterationExponent: number
  ): Promise<string[]>;
  /** Multi-group: groups is packed uint8 pairs [threshold, count, ...]. */
  slip39_generate_groups(
    masterSecret: ArrayBuffer,
    passphrase: string,
    groupThreshold: number,
    groups: ArrayBuffer,
    iterationExponent: number
  ): string[][];
  slip39_generate_groups_async(
    masterSecret: ArrayBuffer,
    passphrase: string,
    groupThreshold: number,
    groups: ArrayBuffer,
    iterationExponent: number
  ): Promise<string[][]>;
  /** Recover master secret from '\n'-joined mnemonics. */
  slip39_combine(mnemonics: string, passphrase: string): ArrayBuffer;
  slip39_combine_async(
    mnemonics: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  slip39_validate_mnemonic(mnemonic: string): boolean;

  /**
   * Hardware-backed key/value storage.
   *
   * iOS: Keychain (kSecClassGenericPassword,
   *      kSecAttrAccessibleWhenUnlockedThisDeviceOnly), service scoped to
   *      the host app's bundle id.
   * Android: AES-256-GCM master key in AndroidKeystore wraps blobs in
   *      <filesDir>/secure_kv/<sha256(name)>.bin.
   *
   * Key names are restricted to [A-Za-z0-9._-] (≤128 chars) and value
   * payloads to 64 KiB. `secure_kv_get` returns null when the key is
   * absent; backend failures (e.g. master key invalidated after factory
   * reset) surface as CryptoError with reason "unavailable" — the JS
   * wrapper upgrades those to SecureKVUnavailableError.
   */
  /** accessControl is "none" | "biometric" — see AccessControl in
   *  cpp/SecureKVBackend.h. validityWindow (seconds) is honoured only
   *  for the biometric variant; 0 = per-call prompt.
   *  promptTitle / promptSubtitle / promptCancel are platform copy for
   *  the biometric prompt — empty string falls back to defaults. */
  /** `passphrase` (empty string = no wrap) layers an additional
   *  PBKDF2+AES-GCM envelope around the slot bytes before storage,
   *  defending against device + biometric bypass. `passphraseIterations`
   *  is the PBKDF2 cost stored in the envelope header (default 600 000;
   *  range [100 000, 10 000 000]); ignored when `passphrase` is empty. */
  secure_kv_set(
    key: string,
    value: ArrayBuffer,
    accessControl: string,
    validityWindow: number,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string,
    passphraseIterations: number
  ): Promise<void>;
  /** `passphrase` (empty = none) is required iff the stored item is
   *  passphrase-wrapped; rejects with `"passphrase: required"` if the
   *  outer slot is wrapped and `passphrase` is empty, `"passphrase: wrong"`
   *  if it doesn't match. */
  secure_kv_get(
    key: string,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer | null>;
  secure_kv_has(key: string): Promise<boolean>;
  secure_kv_delete(key: string): Promise<void>;
  secure_kv_list(): Promise<string[]>;
  secure_kv_clear(): Promise<void>;
  secure_kv_is_hardware_backed(): Promise<boolean>;
  /** Returns one of `BiometricStatus`'s enum values as a string. */
  secure_kv_biometric_status(): Promise<string>;
  /** Plaintext metadata read; never triggers a biometric prompt or AES
   *  decrypt. Returns an object with `exists`, `accessControl`,
   *  `validityWindow`, `hasPassphrase`, `slotKind`. For missing keys,
   *  only `exists: false` is set. */
  secure_kv_metadata(key: string): Promise<{
    exists: boolean;
    accessControl?: string;
    validityWindow?: number;
    hasPassphrase?: boolean;
    slotKind?: string;
  }>;
  /** Drops cached biometric auth for the given alias (empty string = all
   *  aliases). iOS-only effect: invalidates the per-alias `LAContext`.
   *  No-op on Android — Keystore validity windows can't be cleared from
   *  userland; callers wait for expiry or use `validityWindow: 0`. */
  secure_kv_invalidate_session(alias: string): Promise<void>;
  /** Re-wraps `key`'s slot bytes in place. `oldPassphrase` empty = item
   *  not currently wrapped; `newPassphrase` empty = remove wrap. The
   *  inner slot bytes never cross the JSI boundary. */
  secure_kv_change_passphrase(
    key: string,
    oldPassphrase: string,
    newPassphrase: string,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    newPassphraseIterations: number
  ): Promise<void>;
  /** Switches biometric on/off (or changes `validityWindow`) without
   *  parsing or extracting the slot. The blob bytes pass through C++
   *  between the old and new master key. */
  secure_kv_change_access_control(
    key: string,
    accessControl: string,
    validityWindow: number,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string
  ): Promise<void>;

  /**
   * Native-only signing on top of secureKV slots.
   *
   * Two slot families:
   * - SEED  (set via `secure_kv_bip32_set_seed`): a 16..64-byte BIP-32
   *         seed (BIP-32 spec range; bip39.toSeed gives 64). The bip32_*
   *         read methods derive a child key from this seed on the fly,
   *         sign with it, and zero everything before returning. Curve is
   *         passed per call.
   * - RAW   (set via `secure_kv_raw_set_private`): a single 32-byte
   *         private scalar bound to a curve at provisioning time.
   *         No derivation; the curve travels with the slot so the
   *         raw_* sign methods don't take it as a parameter (it is
   *         enforced from the slot).
   *
   * Path arguments are packed big-endian uint32 indices, 4*N bytes for
   * an N-step path — same format as `bip32_derive`.
   *
   * `secure_kv_bip32_sign_ecdsa` and `secure_kv_raw_sign_ecdsa` return
   * 65 bytes laid out as `[recId, sig[0..64]]`, matching `ecdsa_sign`.
   */
  secure_kv_bip32_set_seed(
    key: string,
    seed: ArrayBuffer,
    accessControl: string,
    validityWindow: number,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string,
    passphraseIterations: number
  ): Promise<void>;
  secure_kv_bip32_fingerprint(
    key: string,
    path: ArrayBuffer,
    curve: string,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<number>;
  secure_kv_bip32_get_public(
    key: string,
    path: ArrayBuffer,
    curve: string,
    compact: boolean,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_bip32_sign_ecdsa(
    key: string,
    path: ArrayBuffer,
    digest: ArrayBuffer,
    curve: string,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_bip32_sign_schnorr(
    key: string,
    path: ArrayBuffer,
    digest: ArrayBuffer,
    aux: ArrayBuffer | null,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_bip32_sign_schnorr_taproot(
    key: string,
    path: ArrayBuffer,
    digest: ArrayBuffer,
    merkleRoot: ArrayBuffer | null,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_bip32_sign_ed25519(
    key: string,
    path: ArrayBuffer,
    msg: ArrayBuffer,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_bip32_ecdh(
    key: string,
    path: ArrayBuffer,
    peerPub: ArrayBuffer,
    curve: string,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;

  /** Reads a SEED slot (auth + optional unwrap with `storagePassphrase`)
   *  and re-wraps it under `exportPassphrase`. Returns the envelope as
   *  raw bytes — caller chooses base64/hex/QR encoding. */
  secure_kv_bip32_export_seed(
    key: string,
    exportPassphrase: string,
    storagePassphrase: string,
    exportIterations: number,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string
  ): Promise<ArrayBuffer>;
  /** Decrypts an export envelope and writes the SEED slot under `key`.
   *  If `storagePassphrase` is non-empty, re-wraps it under storage
   *  layer too. */
  secure_kv_bip32_import_seed(
    key: string,
    envelope: ArrayBuffer,
    exportPassphrase: string,
    accessControl: string,
    validityWindow: number,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    storagePassphrase: string,
    storageIterations: number
  ): Promise<void>;

  secure_kv_raw_set_private(
    key: string,
    priv: ArrayBuffer,
    curve: string,
    accessControl: string,
    validityWindow: number,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string,
    passphraseIterations: number
  ): Promise<void>;
  secure_kv_raw_get_public(
    key: string,
    compact: boolean,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_raw_sign_ecdsa(
    key: string,
    digest: ArrayBuffer,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_raw_sign_schnorr(
    key: string,
    digest: ArrayBuffer,
    aux: ArrayBuffer | null,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_raw_sign_schnorr_taproot(
    key: string,
    digest: ArrayBuffer,
    merkleRoot: ArrayBuffer | null,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_raw_sign_ed25519(
    key: string,
    msg: ArrayBuffer,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;
  secure_kv_raw_ecdh(
    key: string,
    peerPub: ArrayBuffer,
    promptTitle: string,
    promptSubtitle: string,
    promptCancel: string,
    passphrase: string
  ): Promise<ArrayBuffer>;

  /**
   * Standalone biometric prompt — UX gate, **not** a cryptographic
   * gate. Use `secure_kv_*_sign_*` for high-assurance flows, where
   * authentication is bound to a Keystore / Keychain operation.
   *
   * `biometric_status` is the same underlying check as
   * `secure_kv_biometric_status`; both share the BiometricStatus
   * enum string set.
   *
   * `biometric_authenticate` shows a system biometric prompt with the
   * given labels (empty strings are replaced with platform-appropriate
   * defaults on the native side) and resolves on success. Rejection
   * messages start with `"user canceled: "` for user-driven dismissals
   * and `"biometric failed: "` for hard failures.
   */
  biometric_status(): Promise<string>;
  biometric_authenticate(
    title: string,
    subtitle: string,
    cancelLabel: string
  ): Promise<void>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('ReactNativeCryptoLib');

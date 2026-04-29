import { type Bip32Curve, encodePath, packPath } from './bip32-utils';
import { raw, toArrayBuffer } from './buffer';
import { type Curve, type EcdsaSignature } from './ecdsa';
import { wrapNativeAsync } from './errors';

/**
 * Per-item access-control gating for secureKV. Discriminated union so
 * future variants (passcode-only, biometric-or-passcode, …) can be
 * added without breaking existing call sites.
 *
 * - `'none'` — no prompt. Item is readable while the device is unlocked.
 * - `'biometric'` — reads trigger a system biometric prompt (Face ID /
 *   Touch ID / fingerprint). The item is bound to "current biometric
 *   set" semantics on both platforms, so re-enrolling biometrics
 *   invalidates the item.
 *   - `validityWindow` (seconds, default `0` = per-call) — after one
 *     successful prompt, subsequent reads of this item within the
 *     window are silent. Useful for batch operations (signing N inputs
 *     of a tx in a row). Set to `0` to require the prompt every time.
 */
export type AccessControlOptions =
  | { accessControl: 'none' }
  | { accessControl: 'biometric'; validityWindow?: number };

/** Legacy single-string alias of `AccessControl`. Kept as a type-only
 *  re-export for callers that read just the discriminator value. */
export type AccessControl = AccessControlOptions['accessControl'];

/** Snapshot of biometric availability — see [secureKV.biometricStatus]. */
export type BiometricStatus =
  | 'available'
  | 'no_hardware'
  | 'not_enrolled'
  | 'hardware_unavailable'
  | 'security_update_required'
  | 'unsupported_os';

const DEFAULT_AC: AccessControlOptions = { accessControl: 'none' };

function windowOf(opts: AccessControlOptions): number {
  return opts.accessControl === 'biometric' ? (opts.validityWindow ?? 0) : 0;
}

// --- generic blob slot (tag 0x00) ------------------------------------------

const set = wrapNativeAsync(
  async (
    key: string,
    value: Uint8Array,
    options: AccessControlOptions = DEFAULT_AC
  ): Promise<void> => {
    await raw.secure_kv_set(
      key,
      toArrayBuffer(value),
      options.accessControl,
      windowOf(options)
    );
  }
);

const get = wrapNativeAsync(async (key: string): Promise<Uint8Array | null> => {
  const buf = await raw.secure_kv_get(key);
  return buf === null ? null : new Uint8Array(buf);
});

const has = wrapNativeAsync(
  async (key: string): Promise<boolean> => raw.secure_kv_has(key)
);

const remove = wrapNativeAsync(
  async (key: string): Promise<void> => raw.secure_kv_delete(key)
);

const list = wrapNativeAsync(
  async (): Promise<string[]> => raw.secure_kv_list()
);

const clear = wrapNativeAsync(async (): Promise<void> => raw.secure_kv_clear());

const isHardwareBacked = wrapNativeAsync(
  async (): Promise<boolean> => raw.secure_kv_is_hardware_backed()
);

const biometricStatus = wrapNativeAsync(
  async (): Promise<BiometricStatus> =>
    (await raw.secure_kv_biometric_status()) as BiometricStatus
);

// --- BIP-32 / SLIP-10 derivation slot (tag 0x01) ---------------------------

function pathBuf(path: string | number[]): ArrayBuffer {
  return typeof path === 'string' ? encodePath(path) : packPath(path);
}

const bip32_setSeed = wrapNativeAsync(
  async (
    alias: string,
    seed: Uint8Array,
    options: AccessControlOptions = DEFAULT_AC
  ): Promise<void> => {
    await raw.secure_kv_bip32_set_seed(
      alias,
      toArrayBuffer(seed),
      options.accessControl,
      windowOf(options)
    );
  }
);

const bip32_fingerprint = wrapNativeAsync(
  async (
    alias: string,
    path: string | number[],
    curve: Bip32Curve
  ): Promise<number> =>
    raw.secure_kv_bip32_fingerprint(alias, pathBuf(path), curve)
);

const bip32_getPublicKey = wrapNativeAsync(
  async (
    alias: string,
    path: string | number[],
    curve: Bip32Curve,
    compact: boolean = true
  ): Promise<Uint8Array> =>
    new Uint8Array(
      await raw.secure_kv_bip32_get_public(alias, pathBuf(path), curve, compact)
    )
);

const bip32_signEcdsa = wrapNativeAsync(
  async (
    alias: string,
    path: string | number[],
    digest: Uint8Array,
    curve: Curve
  ): Promise<EcdsaSignature> => {
    const res = new Uint8Array(
      await raw.secure_kv_bip32_sign_ecdsa(
        alias,
        pathBuf(path),
        toArrayBuffer(digest),
        curve
      )
    );
    return { signature: res.slice(1), recId: res[0] as number };
  }
);

const bip32_signSchnorr = wrapNativeAsync(
  async (
    alias: string,
    path: string | number[],
    digest: Uint8Array,
    aux?: Uint8Array
  ): Promise<Uint8Array> =>
    new Uint8Array(
      await raw.secure_kv_bip32_sign_schnorr(
        alias,
        pathBuf(path),
        toArrayBuffer(digest),
        aux ? toArrayBuffer(aux) : null
      )
    )
);

const bip32_signSchnorrTaproot = wrapNativeAsync(
  async (
    alias: string,
    path: string | number[],
    digest: Uint8Array,
    merkleRoot?: Uint8Array
  ): Promise<Uint8Array> =>
    new Uint8Array(
      await raw.secure_kv_bip32_sign_schnorr_taproot(
        alias,
        pathBuf(path),
        toArrayBuffer(digest),
        merkleRoot ? toArrayBuffer(merkleRoot) : null
      )
    )
);

const bip32_signEd25519 = wrapNativeAsync(
  async (
    alias: string,
    path: string | number[],
    msg: Uint8Array
  ): Promise<Uint8Array> =>
    new Uint8Array(
      await raw.secure_kv_bip32_sign_ed25519(
        alias,
        pathBuf(path),
        toArrayBuffer(msg)
      )
    )
);

const bip32_ecdh = wrapNativeAsync(
  async (
    alias: string,
    path: string | number[],
    peerPub: Uint8Array,
    curve: Curve
  ): Promise<Uint8Array> =>
    new Uint8Array(
      await raw.secure_kv_bip32_ecdh(
        alias,
        pathBuf(path),
        toArrayBuffer(peerPub),
        curve
      )
    )
);

// --- raw 32-byte private key slot (tag 0x02) -------------------------------

const raw_setPrivate = wrapNativeAsync(
  async (
    alias: string,
    priv: Uint8Array,
    curve: Bip32Curve,
    options: AccessControlOptions = DEFAULT_AC
  ): Promise<void> => {
    await raw.secure_kv_raw_set_private(
      alias,
      toArrayBuffer(priv),
      curve,
      options.accessControl,
      windowOf(options)
    );
  }
);

const raw_getPublicKey = wrapNativeAsync(
  async (alias: string, compact: boolean = true): Promise<Uint8Array> =>
    new Uint8Array(await raw.secure_kv_raw_get_public(alias, compact))
);

const raw_signEcdsa = wrapNativeAsync(
  async (alias: string, digest: Uint8Array): Promise<EcdsaSignature> => {
    const res = new Uint8Array(
      await raw.secure_kv_raw_sign_ecdsa(alias, toArrayBuffer(digest))
    );
    return { signature: res.slice(1), recId: res[0] as number };
  }
);

const raw_signSchnorr = wrapNativeAsync(
  async (
    alias: string,
    digest: Uint8Array,
    aux?: Uint8Array
  ): Promise<Uint8Array> =>
    new Uint8Array(
      await raw.secure_kv_raw_sign_schnorr(
        alias,
        toArrayBuffer(digest),
        aux ? toArrayBuffer(aux) : null
      )
    )
);

const raw_signSchnorrTaproot = wrapNativeAsync(
  async (
    alias: string,
    digest: Uint8Array,
    merkleRoot?: Uint8Array
  ): Promise<Uint8Array> =>
    new Uint8Array(
      await raw.secure_kv_raw_sign_schnorr_taproot(
        alias,
        toArrayBuffer(digest),
        merkleRoot ? toArrayBuffer(merkleRoot) : null
      )
    )
);

const raw_signEd25519 = wrapNativeAsync(
  async (alias: string, msg: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(
      await raw.secure_kv_raw_sign_ed25519(alias, toArrayBuffer(msg))
    )
);

const raw_ecdh = wrapNativeAsync(
  async (alias: string, peerPub: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await raw.secure_kv_raw_ecdh(alias, toArrayBuffer(peerPub)))
);

/**
 * Hardware-backed key/value store with optional native-only signing
 * primitives layered on top.
 *
 * **All methods are async.** This is the only domain in the library that
 * crosses an OS-IO / Keychain boundary, so the API is `Promise`-returning
 * end to end. Validation errors surface as Promise rejections too.
 *
 * Three slot families backed by the same encrypted storage:
 *
 * - **Generic blob** (default `set` / `get` / etc.) — opaque user bytes.
 *   Values are `Uint8Array`; keys match `[A-Za-z0-9._-]` (≤128 chars).
 *   Values are capped at 64 KiB.
 * - **`secureKV.bip32`** — provision a 16..64-byte BIP-32 seed (BIP-32
 *   spec range; `bip39.toSeed` gives 64), then
 *   `signEcdsa` / `signSchnorr[Taproot]` / `signEd25519` / `ecdh` / etc.
 *   derive a child key on the fly and sign without ever returning the
 *   private scalar to JS.
 * - **`secureKV.raw`** — provision a single 32-byte private key bound
 *   to a curve, sign with it directly. No derivation.
 *
 * Storage is device-local: never iCloud-synced on iOS, and excluded
 * from Google Drive auto-backup on Android when the host opts in via
 * the bundled `data_extraction_rules.xml`. Blobs are wiped on
 * uninstall or factory reset — see README "secureKV — durability".
 *
 * `get`, `list`, and the sign / derive methods reject with
 * {@link SecureKVUnavailableError} when the OS-managed master key has
 * been invalidated. Treat existing secrets as lost and re-derive them.
 */
export const secureKV = {
  set,
  get,
  has,
  delete: remove,
  list,
  clear,
  isHardwareBacked,
  biometricStatus,

  bip32: {
    setSeed: bip32_setSeed,
    fingerprint: bip32_fingerprint,
    getPublicKey: bip32_getPublicKey,
    signEcdsa: bip32_signEcdsa,
    signSchnorr: bip32_signSchnorr,
    signSchnorrTaproot: bip32_signSchnorrTaproot,
    signEd25519: bip32_signEd25519,
    ecdh: bip32_ecdh,
  },

  raw: {
    setPrivate: raw_setPrivate,
    getPublicKey: raw_getPublicKey,
    signEcdsa: raw_signEcdsa,
    signSchnorr: raw_signSchnorr,
    signSchnorrTaproot: raw_signSchnorrTaproot,
    signEd25519: raw_signEd25519,
    ecdh: raw_ecdh,
  },
};

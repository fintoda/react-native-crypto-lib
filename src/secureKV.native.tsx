import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

/**
 * Access-control gating for `secureKV.set`. Reserved for forward
 * compatibility — only `'none'` is accepted today. Future versions will
 * add `'biometric'` etc. without breaking call sites that already pass
 * (or omit) the third argument.
 */
export type AccessControl = 'none';

const set = wrapNative(
  (
    key: string,
    value: Uint8Array,
    accessControl: AccessControl = 'none'
  ): void => {
    if (accessControl !== 'none') {
      throw new Error(
        `secureKV.set: accessControl='${accessControl}' is not yet supported`
      );
    }
    raw.secure_kv_set(key, toArrayBuffer(value));
  }
);

const get = wrapNative((key: string): Uint8Array | null => {
  const buf = raw.secure_kv_get(key);
  return buf === null ? null : new Uint8Array(buf);
});

const has = wrapNative((key: string): boolean => raw.secure_kv_has(key));

const remove = wrapNative((key: string): void => raw.secure_kv_delete(key));

const list = wrapNative((): string[] => raw.secure_kv_list());

const clear = wrapNative((): void => raw.secure_kv_clear());

const isHardwareBacked = wrapNative((): boolean =>
  raw.secure_kv_is_hardware_backed()
);

/**
 * Hardware-backed key/value store.
 *
 * Values are `Uint8Array`; keys match `[A-Za-z0-9._-]` (≤128 chars).
 * Values are capped at 64 KiB. Storage is device-local: never iCloud-synced
 * on iOS, and excluded from Google Drive auto-backup on Android when the
 * host opts in via the bundled `data_extraction_rules.xml`. Blobs are
 * wiped on uninstall or factory reset — see README "secureKV — durability".
 *
 * `get` and `list` throw {@link SecureKVUnavailableError} when the
 * OS-managed master key has been invalidated; callers should treat
 * existing secrets as lost and re-derive them.
 *
 * Synchronous; no biometric / authentication prompts in this version
 * (`accessControl` is reserved for future opt-in).
 */
export const secureKV = {
  set,
  get,
  has,
  delete: remove,
  list,
  clear,
  isHardwareBacked,
};

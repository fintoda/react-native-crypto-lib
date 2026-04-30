// AES-256: NIST SP 800-38A reference vectors for CBC and CTR plus
// authenticated GCM (Gladman test cases) with AAD round-trips.

import { aes } from '@fintoda/react-native-crypto-lib';
import {
  ascii,
  check,
  eq,
  fromHex,
  hexCheck,
  throws,
  type TestGroup,
} from './harness';

export const aesGroup: TestGroup = {
  id: 'aes',
  title: 'aes',
  description: 'CBC / CTR / GCM round-trips + tamper rejection',
  build: () => {
    // NIST SP 800-38A AES-256 key
    const key = fromHex(
      '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
    );
    const cbcIv = fromHex('000102030405060708090a0b0c0d0e0f');
    const ctrIv = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');

    // F.2.5 first plaintext block
    const ptBlock = fromHex('6bc1bee22e409f96e93d7e117393172a');
    const cbcExp = 'f58c4c04d6e5f1ba779eabfb5f7bfbd6';
    const ctrExp = '601ec313775789a5b7a7f504bbf3d228';

    // GCM Gladman test case (32-byte zero key, 12-byte zero nonce, 16 zero PT)
    const gcmKey = new Uint8Array(32);
    const gcmNonce = new Uint8Array(12);
    const gcmPlain = new Uint8Array(16);
    const gcmCtExp = 'cea7403d4d606b6e074ec5d3baf39d18';
    const gcmTagExp = 'd0d1c8a799996bf0265b98b5d48ab919';

    const cbcEnc = aes.cbc.encrypt(key, cbcIv, ptBlock, 'none');
    const gcmSealed = aes.gcm.encrypt(gcmKey, gcmNonce, gcmPlain);

    return [
      // ---- CBC -----------------------------------------------------------
      hexCheck('cbc encrypt(NIST F.2.5)', cbcEnc, cbcExp),
      check('cbc decrypt(none)', () =>
        eq(aes.cbc.decrypt(key, cbcIv, cbcEnc, 'none'), ptBlock)
      ),
      check('cbc pkcs7 short msg roundtrip', () => {
        const pt = ascii('test padding!!'); // 14 bytes — needs padding
        return eq(
          aes.cbc.decrypt(key, cbcIv, aes.cbc.encrypt(key, cbcIv, pt)),
          pt
        );
      }),
      check('cbc pkcs7 block-aligned roundtrip', () => {
        const pt = ascii('sixteen bytes!!.'); // exactly 16 bytes
        return eq(
          aes.cbc.decrypt(key, cbcIv, aes.cbc.encrypt(key, cbcIv, pt)),
          pt
        );
      }),
      check('cbc pkcs7 multi-block roundtrip', () => {
        const pt = new Uint8Array(64);
        for (let i = 0; i < pt.length; i++) pt[i] = i;
        return eq(
          aes.cbc.decrypt(key, cbcIv, aes.cbc.encrypt(key, cbcIv, pt)),
          pt
        );
      }),
      check('cbc pkcs7 empty plaintext roundtrip', () => {
        const pt = new Uint8Array(0);
        const ct = aes.cbc.encrypt(key, cbcIv, pt);
        // PKCS#7 on empty -> exactly one block of padding
        if (ct.length !== 16) return `expected 16 byte ct, got ${ct.length}`;
        return aes.cbc.decrypt(key, cbcIv, ct).length === 0;
      }),
      throws('cbc decrypt(none) rejects unaligned ct', () =>
        aes.cbc.decrypt(key, cbcIv, new Uint8Array(15), 'none')
      ),
      throws('cbc decrypt(pkcs7) rejects unaligned ct', () =>
        aes.cbc.decrypt(key, cbcIv, new Uint8Array(15))
      ),
      throws('cbc encrypt(none) rejects unaligned pt', () =>
        aes.cbc.encrypt(key, cbcIv, new Uint8Array(15), 'none')
      ),

      // ---- CTR -----------------------------------------------------------
      hexCheck(
        'ctr(NIST F.5.5 first block)',
        aes.ctr.crypt(key, ctrIv, ptBlock),
        ctrExp
      ),
      check('ctr is symmetric (enc(enc(x))==x)', () =>
        eq(
          aes.ctr.crypt(key, ctrIv, aes.ctr.crypt(key, ctrIv, ptBlock)),
          ptBlock
        )
      ),
      check('ctr handles arbitrary length 100B', () => {
        const pt = new Uint8Array(100);
        for (let i = 0; i < 100; i++) pt[i] = i;
        return eq(aes.ctr.crypt(key, ctrIv, aes.ctr.crypt(key, ctrIv, pt)), pt);
      }),

      // ---- GCM -----------------------------------------------------------
      hexCheck('gcm ciphertext (Gladman)', gcmSealed.slice(0, 16), gcmCtExp),
      hexCheck('gcm tag (Gladman)', gcmSealed.slice(16), gcmTagExp),
      check('gcm decrypt round-trip', () =>
        eq(aes.gcm.decrypt(gcmKey, gcmNonce, gcmSealed), gcmPlain)
      ),
      check('gcm rejects tampered ciphertext', () => {
        const t = gcmSealed.slice();
        t[0]! ^= 1;
        try {
          aes.gcm.decrypt(gcmKey, gcmNonce, t);
          return false;
        } catch {
          return true;
        }
      }),
      check('gcm rejects tampered tag', () => {
        const t = gcmSealed.slice();
        t[t.length - 1]! ^= 1;
        try {
          aes.gcm.decrypt(gcmKey, gcmNonce, t);
          return false;
        } catch {
          return true;
        }
      }),
      check('gcm AAD round-trip', () => {
        const aad = ascii('authenticated header');
        const sealed = aes.gcm.encrypt(gcmKey, gcmNonce, ptBlock, aad);
        return eq(aes.gcm.decrypt(gcmKey, gcmNonce, sealed, aad), ptBlock);
      }),
      check('gcm rejects wrong AAD', () => {
        const sealed = aes.gcm.encrypt(
          gcmKey,
          gcmNonce,
          ptBlock,
          ascii('correct')
        );
        try {
          aes.gcm.decrypt(gcmKey, gcmNonce, sealed, ascii('wrong'));
          return false;
        } catch {
          return true;
        }
      }),
      check('gcm AAD-only (zero-length plaintext)', () => {
        const aad = ascii('header only');
        const sealed = aes.gcm.encrypt(
          gcmKey,
          gcmNonce,
          new Uint8Array(0),
          aad
        );
        // Only the 16-byte GCM tag should be returned for empty plaintext
        if (sealed.length !== 16) return `len=${sealed.length}`;
        return aes.gcm.decrypt(gcmKey, gcmNonce, sealed, aad).length === 0;
      }),
      check('gcm large 4 KiB plaintext round-trip', () => {
        const pt = new Uint8Array(4096);
        for (let i = 0; i < pt.length; i++) pt[i] = i & 0xff;
        const sealed = aes.gcm.encrypt(gcmKey, gcmNonce, pt);
        return eq(aes.gcm.decrypt(gcmKey, gcmNonce, sealed), pt);
      }),
      check('gcm rejects truncated ciphertext (no tag)', () => {
        try {
          aes.gcm.decrypt(gcmKey, gcmNonce, new Uint8Array(8));
          return false;
        } catch {
          return true;
        }
      }),
    ];
  },
};

import { describe, it, expect } from '@jest/globals';
import {
  encodePath,
  packPath,
  readBeU32,
  parseNode,
  HARDENED_OFFSET,
  NODE_SIZE,
} from '../bip32-utils';

describe('readBeU32', () => {
  it('reads zero', () => {
    expect(readBeU32(new Uint8Array([0, 0, 0, 0]), 0)).toBe(0);
  });

  it('reads 1', () => {
    expect(readBeU32(new Uint8Array([0, 0, 0, 1]), 0)).toBe(1);
  });

  it('reads 0x80000000 without going negative', () => {
    expect(readBeU32(new Uint8Array([0x80, 0, 0, 0]), 0)).toBe(0x80000000);
  });

  it('reads 0xffffffff', () => {
    expect(readBeU32(new Uint8Array([0xff, 0xff, 0xff, 0xff]), 0)).toBe(
      0xffffffff
    );
  });

  it('reads at offset', () => {
    const buf = new Uint8Array([0, 0, 0x01, 0x02, 0x03, 0x04]);
    expect(readBeU32(buf, 2)).toBe(0x01020304);
  });
});

describe('encodePath', () => {
  it("parses \"m/44'/0'/0'/0/0\"", () => {
    const buf = encodePath("m/44'/0'/0'/0/0");
    const view = new DataView(buf);
    expect(view.byteLength).toBe(20); // 5 indices * 4 bytes
    expect(view.getUint32(0, false)).toBe(44 + HARDENED_OFFSET);
    expect(view.getUint32(4, false)).toBe(0 + HARDENED_OFFSET);
    expect(view.getUint32(8, false)).toBe(0 + HARDENED_OFFSET);
    expect(view.getUint32(12, false)).toBe(0);
    expect(view.getUint32(16, false)).toBe(0);
  });

  it('supports h suffix', () => {
    const buf = encodePath('m/44h/0h');
    const view = new DataView(buf);
    expect(view.getUint32(0, false)).toBe(44 + HARDENED_OFFSET);
    expect(view.getUint32(4, false)).toBe(0 + HARDENED_OFFSET);
  });

  it('handles path without m prefix', () => {
    const buf = encodePath("44'/0");
    const view = new DataView(buf);
    expect(view.byteLength).toBe(8);
    expect(view.getUint32(0, false)).toBe(44 + HARDENED_OFFSET);
    expect(view.getUint32(4, false)).toBe(0);
  });

  it('handles empty path', () => {
    const buf = encodePath('m');
    expect(buf.byteLength).toBe(0);
  });

  it('throws on negative index', () => {
    expect(() => encodePath('m/-1')).toThrow('invalid path component');
  });

  it('throws on non-integer', () => {
    expect(() => encodePath('m/1.5')).toThrow('invalid path component');
  });

  it('throws on index >= HARDENED_OFFSET', () => {
    expect(() => encodePath(`m/${HARDENED_OFFSET}`)).toThrow(
      'invalid path component'
    );
  });

  it('trims whitespace', () => {
    const buf = encodePath('  m/0  ');
    expect(buf.byteLength).toBe(4);
  });
});

describe('packPath', () => {
  it('packs simple indices', () => {
    const buf = packPath([0, 1, 2]);
    const view = new DataView(buf);
    expect(view.byteLength).toBe(12);
    expect(view.getUint32(0, false)).toBe(0);
    expect(view.getUint32(4, false)).toBe(1);
    expect(view.getUint32(8, false)).toBe(2);
  });

  it('packs hardened indices', () => {
    const buf = packPath([44 + HARDENED_OFFSET]);
    const view = new DataView(buf);
    expect(view.getUint32(0, false)).toBe(44 + HARDENED_OFFSET);
  });

  it('handles empty array', () => {
    expect(packPath([]).byteLength).toBe(0);
  });

  it('throws on negative', () => {
    expect(() => packPath([-1])).toThrow('invalid path index');
  });

  it('throws on non-integer', () => {
    expect(() => packPath([1.5])).toThrow('invalid path index');
  });

  it('throws on > 0xffffffff', () => {
    expect(() => packPath([0x100000000])).toThrow('invalid path index');
  });
});

describe('parseNode', () => {
  function makeNodeBlob(opts: {
    curveTag?: number;
    hasPrivate?: number;
    depth?: number;
    parentFp?: number;
    childNum?: number;
  }): Uint8Array {
    const buf = new Uint8Array(NODE_SIZE);
    buf[0] = opts.curveTag ?? 0;
    buf[1] = opts.hasPrivate ?? 1;
    buf[2] = opts.depth ?? 3;
    // parentFingerprint at [3..6]
    const fp = opts.parentFp ?? 0xdeadbeef;
    buf[3] = (fp >>> 24) & 0xff;
    buf[4] = (fp >>> 16) & 0xff;
    buf[5] = (fp >>> 8) & 0xff;
    buf[6] = fp & 0xff;
    // childNumber at [7..10]
    const cn = opts.childNum ?? 42;
    buf[7] = (cn >>> 24) & 0xff;
    buf[8] = (cn >>> 16) & 0xff;
    buf[9] = (cn >>> 8) & 0xff;
    buf[10] = cn & 0xff;
    // chainCode [11..42], privateKey [43..74], publicKey [75..107]
    buf.fill(0xcc, 11, 43); // chainCode
    buf.fill(0xaa, 43, 75); // privateKey
    buf.fill(0xbb, 75, 108); // publicKey
    return buf;
  }

  it('parses secp256k1 private node', () => {
    const blob = makeNodeBlob({ curveTag: 0, hasPrivate: 1, depth: 5 });
    const node = parseNode(blob);
    expect(node.curve).toBe('secp256k1');
    expect(node.depth).toBe(5);
    expect(node.parentFingerprint).toBe(0xdeadbeef);
    expect(node.childNumber).toBe(42);
    expect(node.chainCode.length).toBe(32);
    expect(node.privateKey).not.toBeNull();
    expect(node.privateKey!.length).toBe(32);
    expect(node.publicKey.length).toBe(33);
    expect(node.raw).toBe(blob);
  });

  it('parses nist256p1 public-only node', () => {
    const blob = makeNodeBlob({ curveTag: 1, hasPrivate: 0 });
    const node = parseNode(blob);
    expect(node.curve).toBe('nist256p1');
    expect(node.privateKey).toBeNull();
  });

  it('parses ed25519 node', () => {
    const blob = makeNodeBlob({ curveTag: 2 });
    expect(parseNode(blob).curve).toBe('ed25519');
  });

  it('throws on wrong size', () => {
    expect(() => parseNode(new Uint8Array(64))).toThrow('108-byte');
  });

  it('throws on unknown curve tag', () => {
    const blob = makeNodeBlob({ curveTag: 99 });
    expect(() => parseNode(blob)).toThrow('unknown curve tag');
  });

  it('reads parentFingerprint >= 0x80000000 correctly', () => {
    const blob = makeNodeBlob({ parentFp: 0x80000001 });
    expect(parseNode(blob).parentFingerprint).toBe(0x80000001);
  });
});

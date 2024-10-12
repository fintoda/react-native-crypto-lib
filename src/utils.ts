import { Buffer } from 'buffer';

export function base64Encode(src: string | Uint8Array): string {
  return Buffer.from(src).toString('base64');
}

export function base64Decode(src: string): Uint8Array {
  return new Uint8Array(Buffer.from(src, 'base64'));
}

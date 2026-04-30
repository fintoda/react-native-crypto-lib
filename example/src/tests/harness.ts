// Test harness for runtime test groups. Each group exports a builder that
// returns a list of `TestCase`. The screen runs them sequentially and
// reports per-case pass/fail.
//
// Helpers (`check`, `hexCheck`, `throws`, plus their async siblings) wrap a
// closure into a `TestCase` so individual lines stay readable. Each helper
// turns a thrown exception into `{ pass:false, detail: <message> }`.

export type TestResult = { pass: boolean; detail?: string };

export type TestCase = {
  name: string;
  run: () => Promise<TestResult>;
};

export type TestGroup = {
  id: string;
  title: string;
  description?: string;
  /** Builds the case list. Async to allow per-suite preflight (e.g. clear). */
  build: () => TestCase[] | Promise<TestCase[]>;
};

// ---------- shared encoding helpers ---------------------------------------

export const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export const fromHex = (h: string): Uint8Array =>
  new Uint8Array(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));

export const ascii = (s: string): Uint8Array =>
  Uint8Array.from(s, (c) => c.charCodeAt(0));

export function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---------- case builders -------------------------------------------------

type CheckFn = () => boolean | string | Promise<boolean | string>;

/** True/false test. Returning a string is treated as failure with detail. */
export function check(name: string, fn: CheckFn): TestCase {
  return {
    name,
    run: async () => {
      try {
        const r = await fn();
        if (typeof r === 'string') return { pass: false, detail: r };
        return { pass: r };
      } catch (e: unknown) {
        return { pass: false, detail: String(e) };
      }
    },
  };
}

/** Compares actual bytes to expected hex. */
export function hexCheck(
  name: string,
  actual: Uint8Array | (() => Uint8Array | Promise<Uint8Array>),
  expected: string
): TestCase {
  return {
    name,
    run: async () => {
      try {
        const bytes = typeof actual === 'function' ? await actual() : actual;
        const hex = toHex(bytes);
        return {
          pass: hex === expected,
          detail: hex !== expected ? `got ${hex}` : undefined,
        };
      } catch (e: unknown) {
        return { pass: false, detail: String(e) };
      }
    },
  };
}

/** Asserts that the closure throws. */
export function throws(
  name: string,
  fn: () => unknown | Promise<unknown>
): TestCase {
  return {
    name,
    run: async () => {
      try {
        await fn();
        return { pass: false, detail: 'did not throw' };
      } catch {
        return { pass: true };
      }
    },
  };
}

/**
 * Asserts that the closure throws and the thrown error has `name === expected`.
 * Useful for verifying error-class classification (WrongPassphraseError etc).
 */
export function throwsWithName(
  testName: string,
  expectedErrorName: string,
  fn: () => unknown | Promise<unknown>
): TestCase {
  return {
    name: testName,
    run: async () => {
      try {
        await fn();
        return { pass: false, detail: 'did not throw' };
      } catch (e: unknown) {
        const got = (e as { name?: string }).name ?? '';
        return {
          pass: got === expectedErrorName,
          detail: got !== expectedErrorName ? `threw ${got}` : undefined,
        };
      }
    },
  };
}

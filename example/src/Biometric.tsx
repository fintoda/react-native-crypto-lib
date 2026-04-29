import { useState, useCallback } from 'react';
import {
  ScrollView,
  Text,
  View,
  StyleSheet,
  Pressable,
  Platform,
} from 'react-native';
import {
  secureKV,
  hash,
  ecdsa,
  schnorr,
  rng,
  CryptoError,
} from '@fintoda/react-native-crypto-lib';

// Interactive test surface for the biometric (`accessControl: 'biometric'`)
// path. Provisioning never prompts; reads / signs trigger the system
// biometric dialog. Each row exercises one entrypoint and shows the
// outcome plus how long it took (useful as evidence that the OS prompt
// actually appeared rather than silently no-opping).

type RunState =
  | { status: 'idle' }
  | { status: 'running' }
  | { status: 'ok'; ms: number; detail: string }
  | { status: 'cancel'; ms: number; detail: string }
  | { status: 'fail'; ms: number; detail: string };

type StepFn = () => Promise<string>;

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function ascii(s: string): Uint8Array {
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

const KEY_BLOB = 'demo.bio.blob';
const KEY_SEED = 'demo.bio.seed';
const KEY_RAW = 'demo.bio.raw';

// 32-byte fixed seed so signatures are reproducible across runs without
// stashing them anywhere. Values shown to the user are derived public
// keys / signatures only.
const FIXED_SEED = (() => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (i * 17 + 1) & 0xff;
  return out;
})();

async function setBiometricBlob(): Promise<string> {
  const value = ascii('biometric blob payload');
  await secureKV.set(KEY_BLOB, value, { accessControl: 'biometric' });
  return `Stored ${value.length}B at "${KEY_BLOB}"`;
}

async function readBiometricBlob(): Promise<string> {
  const got = await secureKV.get(KEY_BLOB);
  if (got === null) return 'returned null (provision first)';
  return `Read ${got.length}B: "${String.fromCharCode(...got)}"`;
}

async function setBiometricSeed(): Promise<string> {
  await secureKV.bip32.setSeed(KEY_SEED, FIXED_SEED, {
    accessControl: 'biometric',
  });
  return `Stored 32B BIP-32 seed at "${KEY_SEED}"`;
}

async function signBiometricEcdsa(): Promise<string> {
  const digest = hash.sha256(ascii('biometric ecdsa demo'));
  const sig = await secureKV.bip32.signEcdsa(
    KEY_SEED,
    "m/44'/0'/0'/0/0",
    digest,
    'secp256k1'
  );
  // Verify against the derived pub so we know the prompt's success path
  // really gave us the right key.
  const pub = await secureKV.bip32.getPublicKey(
    KEY_SEED,
    "m/44'/0'/0'/0/0",
    'secp256k1'
  );
  const ok = ecdsa.verify(pub, sig.signature, digest);
  return `Sig: ${toHex(sig.signature).slice(0, 16)}... verify=${ok}`;
}

async function signBiometricSchnorr(): Promise<string> {
  const digest = hash.sha256(ascii('biometric schnorr demo'));
  const sig = await secureKV.bip32.signSchnorrTaproot(
    KEY_SEED,
    "m/86'/0'/0'/0/0",
    digest
  );
  const compressed = await secureKV.bip32.getPublicKey(
    KEY_SEED,
    "m/86'/0'/0'/0/0",
    'secp256k1'
  );
  const xOnly = compressed.slice(1, 33);
  const tweaked = schnorr.tweakPublic(xOnly).pub;
  const ok = schnorr.verify(tweaked, sig, digest);
  return `Taproot sig: ${toHex(sig).slice(0, 16)}... verify=${ok}`;
}

async function setBiometricRaw(): Promise<string> {
  const priv = ecdsa.randomPrivate('secp256k1');
  await secureKV.raw.setPrivate(KEY_RAW, priv, 'secp256k1', {
    accessControl: 'biometric',
  });
  // The priv lives in JS for this one call; overwrite our copy so a heap
  // dump after this point can't recover it.
  priv.fill(0);
  return `Stored 32B raw secp256k1 priv at "${KEY_RAW}"`;
}

async function signBiometricRaw(): Promise<string> {
  const digest = rng.bytes(32);
  const sig = await secureKV.raw.signEcdsa(KEY_RAW, digest);
  const pub = await secureKV.raw.getPublicKey(KEY_RAW);
  const ok = ecdsa.verify(pub, sig.signature, digest);
  return `Sig: ${toHex(sig.signature).slice(0, 16)}... verify=${ok}`;
}

async function cleanup(): Promise<string> {
  await secureKV.delete(KEY_BLOB);
  await secureKV.delete(KEY_SEED);
  await secureKV.delete(KEY_RAW);
  return `Deleted ${KEY_BLOB}, ${KEY_SEED}, ${KEY_RAW}`;
}

const STEPS: { id: string; label: string; fn: StepFn }[] = [
  {
    id: 'set_blob',
    label: '1. Provision biometric BLOB',
    fn: setBiometricBlob,
  },
  {
    id: 'read_blob',
    label: '2. Read BLOB → expect Face ID / Touch ID',
    fn: readBiometricBlob,
  },
  {
    id: 'set_seed',
    label: '3. Provision biometric BIP-32 seed',
    fn: setBiometricSeed,
  },
  {
    id: 'sign_ecdsa',
    label: '4. Sign ECDSA → expect prompt',
    fn: signBiometricEcdsa,
  },
  {
    id: 'sign_schnorr',
    label: '5. Sign Schnorr/Taproot → expect prompt',
    fn: signBiometricSchnorr,
  },
  {
    id: 'set_raw',
    label: '6. Provision biometric raw priv',
    fn: setBiometricRaw,
  },
  {
    id: 'sign_raw',
    label: '7. Sign with raw key → expect prompt',
    fn: signBiometricRaw,
  },
  { id: 'cleanup', label: '8. Delete all biometric items', fn: cleanup },
];

// User-cancel detection. iOS Keychain returns errSecUserCanceled (-128)
// when the prompt is dismissed; the C++ wrapper surfaces it via
// "OSStatus -128". Android (Phase 2) will use BiometricPrompt's
// USER_CANCELED constant. Match both so the UI distinguishes a polite
// cancel from a real failure.
function isCancel(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return (
    msg.includes('OSStatus -128') ||
    msg.includes('User canceled') ||
    msg.includes('user canceled') ||
    msg.includes('UserCancel')
  );
}

export default function Biometric() {
  const [states, setStates] = useState<Record<string, RunState>>({});

  const runStep = useCallback(async (id: string, fn: StepFn) => {
    setStates((s) => ({ ...s, [id]: { status: 'running' } }));
    const t0 = Date.now();
    try {
      const detail = await fn();
      const ms = Date.now() - t0;
      setStates((s) => ({ ...s, [id]: { status: 'ok', ms, detail } }));
    } catch (e: unknown) {
      const ms = Date.now() - t0;
      const detail =
        e instanceof CryptoError
          ? `${e.function}: ${e.reason}`
          : e instanceof Error
            ? e.message
            : String(e);
      const status: 'cancel' | 'fail' = isCancel(e) ? 'cancel' : 'fail';
      setStates((s) => ({ ...s, [id]: { status, ms, detail } }));
    }
  }, []);

  const runAll = useCallback(async () => {
    for (const { id, fn } of STEPS) {
      await runStep(id, fn);
    }
  }, [runStep]);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.header}>Biometric (Phase 1)</Text>
      <Text style={styles.subtitle}>
        Each step exercises a `secureKV` entrypoint with{' '}
        <Text style={styles.code}>accessControl: 'biometric'</Text>. Reads and
        signs trigger a system biometric prompt; provisioning does not. On
        Android, all 'biometric' steps refuse with a clear error pending the
        Phase 2 implementation.
      </Text>

      {Platform.OS === 'android' && (
        <View style={styles.warn}>
          <Text style={styles.warnText}>
            Running on Android. Provisioning steps will fail with "biometric is
            not yet implemented" — this is expected.
          </Text>
        </View>
      )}

      <Pressable style={styles.runAllButton} onPress={runAll}>
        <Text style={styles.runAllButtonText}>Run all steps in order</Text>
      </Pressable>

      {STEPS.map((step) => {
        const state = states[step.id] ?? { status: 'idle' };
        return (
          <View key={step.id} style={styles.row}>
            <Pressable
              style={[
                styles.stepButton,
                state.status === 'running' && styles.stepButtonBusy,
              ]}
              onPress={() => runStep(step.id, step.fn)}
              disabled={state.status === 'running'}
            >
              <Text style={styles.stepButtonText}>{step.label}</Text>
            </Pressable>

            <StatusLine state={state} />
          </View>
        );
      })}
    </ScrollView>
  );
}

function StatusLine({ state }: { state: RunState }) {
  if (state.status === 'idle') {
    return <Text style={styles.statusIdle}>idle</Text>;
  }
  if (state.status === 'running') {
    return <Text style={styles.statusRunning}>running…</Text>;
  }
  if (state.status === 'ok') {
    return (
      <Text style={styles.statusOk}>
        OK ({state.ms}ms) — {state.detail}
      </Text>
    );
  }
  if (state.status === 'cancel') {
    return (
      <Text style={styles.statusCancel}>
        CANCELLED ({state.ms}ms) — {state.detail}
      </Text>
    );
  }
  return (
    <Text style={styles.statusFail}>
      FAIL ({state.ms}ms) — {state.detail}
    </Text>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
    paddingBottom: 48,
  },
  header: {
    fontSize: 20,
    fontWeight: '700',
    marginBottom: 6,
  },
  subtitle: {
    fontSize: 13,
    color: '#555',
    marginBottom: 12,
  },
  code: {
    fontFamily: 'Courier',
    backgroundColor: '#eee',
  },
  warn: {
    backgroundColor: '#fff3cd',
    borderColor: '#ffeeba',
    borderWidth: 1,
    borderRadius: 6,
    padding: 10,
    marginBottom: 12,
  },
  warnText: {
    fontSize: 12,
    color: '#856404',
  },
  runAllButton: {
    backgroundColor: '#007AFF',
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
    marginBottom: 16,
  },
  runAllButtonText: {
    color: '#fff',
    fontSize: 15,
    fontWeight: '600',
  },
  row: {
    marginBottom: 14,
  },
  stepButton: {
    backgroundColor: '#e7f0ff',
    borderColor: '#007AFF',
    borderWidth: 1,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 6,
    marginBottom: 4,
  },
  stepButtonBusy: {
    opacity: 0.6,
  },
  stepButtonText: {
    color: '#0050a0',
    fontSize: 13,
    fontWeight: '500',
  },
  statusIdle: {
    fontSize: 11,
    fontFamily: 'Courier',
    color: '#888',
  },
  statusRunning: {
    fontSize: 11,
    fontFamily: 'Courier',
    color: '#007AFF',
  },
  statusOk: {
    fontSize: 11,
    fontFamily: 'Courier',
    color: '#2a7a2a',
  },
  statusCancel: {
    fontSize: 11,
    fontFamily: 'Courier',
    color: '#aa6600',
  },
  statusFail: {
    fontSize: 11,
    fontFamily: 'Courier',
    color: '#c00',
  },
});

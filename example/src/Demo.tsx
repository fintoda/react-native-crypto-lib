import { useState } from 'react';
import { ScrollView, Text, View, StyleSheet, Pressable } from 'react-native';
import {
  hash,
  ecdsa,
  schnorr,
  ed25519,
  aes,
  bip39,
  bip32,
  slip39,
  rng,
} from '@fintoda/react-native-crypto-lib';

type DemoResult = { title: string; lines: string[] };

function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function encode(str: string): Uint8Array {
  const buf = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
  return buf;
}

function decode(data: Uint8Array): string {
  return String.fromCharCode(...data);
}

function runBip39Bip32Ecdsa(): DemoResult {
  const mnemonic = bip39.generate(128);
  const seed = bip39.toSeedSync(mnemonic, '');
  const root = bip32.fromSeed(seed, 'secp256k1');
  const child = bip32.derive(root, "m/44'/0'/0'/0/0");
  const msg = hash.sha256(encode('Hello, crypto!'));
  const { signature, recId } = ecdsa.sign(child.privateKey!, msg);
  const valid = ecdsa.verify(child.publicKey, signature, msg);
  const recovered = ecdsa.recover(signature, msg, recId);

  return {
    title: 'BIP-39 -> BIP-32 -> ECDSA',
    lines: [
      `Mnemonic: ${mnemonic}`,
      `Seed: ${toHex(seed).slice(0, 32)}...`,
      `Child pubkey: ${toHex(child.publicKey)}`,
      `Message hash: ${toHex(msg)}`,
      `Signature: ${toHex(signature).slice(0, 32)}...`,
      `Recovery ID: ${recId}`,
      `Verify: ${valid ? 'PASS' : 'FAIL'}`,
      `Recovered matches: ${toHex(recovered).slice(0, 16)}...`,
    ],
  };
}

function runSchnorrSign(): DemoResult {
  const priv = ecdsa.randomPrivate('secp256k1');
  const pub = schnorr.getPublic(priv);
  const msg = hash.sha256(encode('Schnorr BIP-340 test'));
  const aux = rng.bytes(32);
  const sig = schnorr.sign(priv, msg, aux);
  const valid = schnorr.verify(pub, sig, msg);

  return {
    title: 'Schnorr (BIP-340)',
    lines: [
      `x-only pubkey: ${toHex(pub)}`,
      `Signature: ${toHex(sig).slice(0, 32)}...`,
      `Verify: ${valid ? 'PASS' : 'FAIL'}`,
    ],
  };
}

function runEd25519Sign(): DemoResult {
  const priv = rng.bytes(32);
  const pub = ed25519.getPublic(priv);
  const msg = encode('Ed25519 RFC 8032 test');
  const sig = ed25519.sign(priv, msg);
  const valid = ed25519.verify(pub, sig, msg);

  return {
    title: 'Ed25519',
    lines: [
      `Public key: ${toHex(pub)}`,
      `Signature: ${toHex(sig).slice(0, 32)}...`,
      `Verify: ${valid ? 'PASS' : 'FAIL'}`,
    ],
  };
}

function runAesRoundTrip(): DemoResult {
  const key = rng.bytes(32);
  const iv = rng.bytes(16);
  const nonce = rng.bytes(12);
  const plaintext = encode('Secret message for AES demo');

  // CBC
  const cbcEnc = aes.cbc.encrypt(key, iv, plaintext);
  const cbcDec = aes.cbc.decrypt(key, iv, cbcEnc);
  const cbcOk = decode(cbcDec) === 'Secret message for AES demo';

  // GCM
  const gcmEnc = aes.gcm.encrypt(key, nonce, plaintext);
  const gcmDec = aes.gcm.decrypt(key, nonce, gcmEnc);
  const gcmOk = decode(gcmDec) === 'Secret message for AES demo';

  return {
    title: 'AES-256 Round-trip',
    lines: [
      `CBC ciphertext: ${toHex(cbcEnc).slice(0, 32)}... (${cbcEnc.length}B)`,
      `CBC decrypt: ${cbcOk ? 'PASS' : 'FAIL'}`,
      `GCM sealed: ${toHex(gcmEnc).slice(0, 32)}... (${gcmEnc.length}B)`,
      `GCM decrypt: ${gcmOk ? 'PASS' : 'FAIL'}`,
    ],
  };
}

function runSlip39SplitCombine(): DemoResult {
  const masterSecret = rng.bytes(16);
  const shares = slip39.generateSync(masterSecret, '', 2, 3, 0);
  const recovered = slip39.combineSync([shares[0]!, shares[2]!], '');
  const match = toHex(masterSecret) === toHex(recovered);

  return {
    title: 'SLIP-39 Split/Combine (2-of-3)',
    lines: [
      `Master secret: ${toHex(masterSecret)}`,
      `Share 1: ${shares[0]!.split(' ').slice(0, 4).join(' ')}...`,
      `Share 2: ${shares[1]!.split(' ').slice(0, 4).join(' ')}...`,
      `Share 3: ${shares[2]!.split(' ').slice(0, 4).join(' ')}...`,
      `Recovered (shares 1+3): ${toHex(recovered)}`,
      `Match: ${match ? 'PASS' : 'FAIL'}`,
    ],
  };
}

const DEMOS = [
  { name: 'BIP-39 -> BIP-32 -> ECDSA', fn: runBip39Bip32Ecdsa },
  { name: 'Schnorr (BIP-340)', fn: runSchnorrSign },
  { name: 'Ed25519', fn: runEd25519Sign },
  { name: 'AES-256 Round-trip', fn: runAesRoundTrip },
  { name: 'SLIP-39 Split/Combine', fn: runSlip39SplitCombine },
];

export default function Demo() {
  const [results, setResults] = useState<DemoResult[]>([]);

  const runAll = () => {
    setResults(DEMOS.map((d) => d.fn()));
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.header}>Usage Demos</Text>
      <Text style={styles.subtitle}>
        Real-world crypto scenarios using the library API.
      </Text>

      <Pressable style={styles.button} onPress={runAll}>
        <Text style={styles.buttonText}>Run All Demos</Text>
      </Pressable>

      {results.map((r, i) => (
        <View key={i} style={styles.card}>
          <Text style={styles.cardTitle}>{r.title}</Text>
          {r.lines.map((line, j) => (
            <Text key={j} style={styles.cardLine}>
              {line}
            </Text>
          ))}
        </View>
      ))}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
    paddingTop: 64,
    paddingBottom: 32,
  },
  header: {
    fontSize: 20,
    fontWeight: '700',
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 13,
    color: '#666',
    marginBottom: 16,
  },
  button: {
    backgroundColor: '#007AFF',
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
    marginBottom: 20,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  card: {
    backgroundColor: '#f5f5f5',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
  },
  cardTitle: {
    fontSize: 14,
    fontWeight: '700',
    marginBottom: 6,
  },
  cardLine: {
    fontSize: 11,
    fontFamily: 'Courier',
    color: '#333',
    marginBottom: 2,
  },
});

// Top-level menu. Lists every test group plus the two interactive screens
// (Demo, Biometric). State is hands-off here — this is just navigation.

import { ScrollView, StyleSheet, Text, View, Pressable } from 'react-native';
import { TEST_GROUPS } from './tests';

export type MenuEntryId = string;

type ExtraEntry = {
  id: MenuEntryId;
  title: string;
  description: string;
  kind: 'extra';
};

const EXTRAS: ExtraEntry[] = [
  {
    id: 'demo',
    title: 'Usage demos',
    description: 'Sample flows: BIP-32→ECDSA, AES, SLIP-39, Ed25519, Schnorr',
    kind: 'extra',
  },
  {
    id: 'biometric',
    title: 'Biometric (interactive)',
    description: 'Live BiometricPrompt / Face ID — taps required',
    kind: 'extra',
  },
];

export default function MenuScreen({
  onSelect,
}: {
  onSelect: (id: MenuEntryId) => void;
}) {
  return (
    <ScrollView contentContainerStyle={styles.content}>
      <Text style={styles.heading}>Crypto runtime tests</Text>
      <Text style={styles.subheading}>
        Each row runs vectors against the native module. Tap to open.
      </Text>

      <Text style={styles.sectionLabel}>Test groups</Text>
      {TEST_GROUPS.map((g) => (
        <Pressable
          key={g.id}
          style={({ pressed }) => [styles.row, pressed && styles.rowPressed]}
          onPress={() => onSelect(g.id)}
        >
          <View style={styles.rowText}>
            <Text style={styles.rowTitle}>{g.title}</Text>
            {g.description && (
              <Text style={styles.rowDescription}>{g.description}</Text>
            )}
          </View>
          <Text style={styles.chevron}>›</Text>
        </Pressable>
      ))}

      <Text style={styles.sectionLabel}>Interactive</Text>
      {EXTRAS.map((e) => (
        <Pressable
          key={e.id}
          style={({ pressed }) => [styles.row, pressed && styles.rowPressed]}
          onPress={() => onSelect(e.id)}
        >
          <View style={styles.rowText}>
            <Text style={styles.rowTitle}>{e.title}</Text>
            <Text style={styles.rowDescription}>{e.description}</Text>
          </View>
          <Text style={styles.chevron}>›</Text>
        </Pressable>
      ))}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  content: {
    paddingTop: 64,
    paddingBottom: 32,
    paddingHorizontal: 16,
  },
  heading: { fontSize: 22, fontWeight: '700' },
  subheading: { fontSize: 13, color: '#666', marginTop: 4, marginBottom: 16 },
  sectionLabel: {
    fontSize: 11,
    fontWeight: '700',
    color: '#888',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginTop: 16,
    marginBottom: 8,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#f7f7f7',
    borderRadius: 8,
    padding: 12,
    marginBottom: 8,
  },
  rowPressed: { backgroundColor: '#e6e6e6' },
  rowText: { flex: 1, paddingRight: 8 },
  rowTitle: { fontSize: 15, fontWeight: '600' },
  rowDescription: { fontSize: 12, color: '#666', marginTop: 2 },
  chevron: { fontSize: 20, color: '#bbb' },
});

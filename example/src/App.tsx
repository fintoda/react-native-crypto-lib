import { useEffect, useState } from 'react';
import { ScrollView, Text, View, StyleSheet } from 'react-native';
import { runAllTests, type TestResult } from './testVectors';

export default function App() {
  const [results, setResults] = useState<TestResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    try {
      setResults(runAllTests());
    } catch (e: unknown) {
      setError(String(e));
    }
  }, []);

  const passed = results.filter((r) => r.pass).length;
  const failed = results.filter((r) => !r.pass).length;
  const total = results.length;

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.header}>Crypto Test Vectors</Text>

      {error && <Text style={styles.error}>Fatal: {error}</Text>}

      {total > 0 && (
        <Text style={[styles.summary, failed > 0 ? styles.fail : styles.pass]}>
          {failed === 0
            ? `ALL ${total} PASSED`
            : `${passed}/${total} passed, ${failed} FAILED`}
        </Text>
      )}

      {results.map((r, i) => (
        <View key={i} style={styles.row}>
          <Text style={r.pass ? styles.pass : styles.fail}>
            {r.pass ? 'PASS' : 'FAIL'}
          </Text>
          <View style={styles.info}>
            <Text style={styles.name}>{r.name}</Text>
            {r.detail && <Text style={styles.detail}>{r.detail}</Text>}
          </View>
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
    marginBottom: 12,
  },
  summary: {
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 16,
    padding: 8,
    borderRadius: 6,
    overflow: 'hidden',
    textAlign: 'center',
  },
  error: {
    color: '#c00',
    fontSize: 14,
    marginBottom: 12,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: 6,
    gap: 8,
  },
  info: {
    flex: 1,
  },
  name: {
    fontSize: 12,
    fontFamily: 'Courier',
  },
  detail: {
    fontSize: 10,
    fontFamily: 'Courier',
    color: '#888',
    marginTop: 2,
  },
  pass: {
    color: '#2a2',
    fontWeight: '700',
    fontSize: 12,
  },
  fail: {
    color: '#c00',
    fontWeight: '700',
    fontSize: 12,
  },
});

import { useEffect, useState } from 'react';
import { ScrollView, Text, View, StyleSheet, Pressable } from 'react-native';
import { runAllTests, type TestResult } from './testVectors';
import Demo from './Demo';

type Tab = 'tests' | 'demo';

function TestVectors() {
  const [results, setResults] = useState<TestResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    runAllTests()
      .then(setResults)
      .catch((e: unknown) => setError(String(e)));
  }, []);

  const passed = results.filter((r) => r.pass).length;
  const failed = results.filter((r) => !r.pass).length;
  const total = results.length;

  return (
    <ScrollView contentContainerStyle={styles.content}>
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

export default function App() {
  const [tab, setTab] = useState<Tab>('tests');

  return (
    <View style={styles.container}>
      <View style={styles.tabs}>
        <Pressable
          style={[styles.tab, tab === 'tests' && styles.activeTab]}
          onPress={() => setTab('tests')}
        >
          <Text
            style={[styles.tabText, tab === 'tests' && styles.activeTabText]}
          >
            Test Vectors
          </Text>
        </Pressable>
        <Pressable
          style={[styles.tab, tab === 'demo' && styles.activeTab]}
          onPress={() => setTab('demo')}
        >
          <Text
            style={[styles.tabText, tab === 'demo' && styles.activeTabText]}
          >
            Usage Demo
          </Text>
        </Pressable>
      </View>

      {tab === 'tests' ? <TestVectors /> : <Demo />}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    paddingTop: 54,
  },
  tabs: {
    flexDirection: 'row',
    borderBottomWidth: 1,
    borderBottomColor: '#ddd',
  },
  tab: {
    flex: 1,
    paddingVertical: 12,
    alignItems: 'center',
  },
  activeTab: {
    borderBottomWidth: 2,
    borderBottomColor: '#007AFF',
  },
  tabText: {
    fontSize: 14,
    fontWeight: '500',
    color: '#888',
  },
  activeTabText: {
    color: '#007AFF',
  },
  content: {
    padding: 16,
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

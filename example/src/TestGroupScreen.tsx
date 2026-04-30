// One screen per `TestGroup`. Builds the case list on mount, then runs each
// case sequentially, updating per-row status as it goes. Re-run is a single
// button at the top.

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator,
  ScrollView,
  StyleSheet,
  Text,
  View,
  Pressable,
} from 'react-native';
import type { TestCase, TestGroup, TestResult } from './tests';

type RowState =
  | { status: 'pending' }
  | { status: 'running' }
  | { status: 'pass' }
  | { status: 'fail'; detail?: string };

type Row = { name: string; state: RowState };

export default function TestGroupScreen({
  group,
  onBack,
}: {
  group: TestGroup;
  onBack: () => void;
}) {
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cancelRef = useRef(false);

  const run = useCallback(async () => {
    setError(null);
    setLoading(true);
    let cases: TestCase[] = [];
    try {
      cases = await Promise.resolve(group.build());
    } catch (e: unknown) {
      setError(`build failed: ${String(e)}`);
      setLoading(false);
      return;
    }
    setRows(cases.map((c) => ({ name: c.name, state: { status: 'pending' } })));
    setLoading(false);
    setRunning(true);
    cancelRef.current = false;

    for (let i = 0; i < cases.length; i++) {
      if (cancelRef.current) break;
      // Mark as running so the user sees progress on long-running ops.
      setRows((prev) => {
        const next = prev.slice();
        next[i] = { name: cases[i]!.name, state: { status: 'running' } };
        return next;
      });
      let result: TestResult;
      try {
        result = await cases[i]!.run();
      } catch (e: unknown) {
        result = { pass: false, detail: String(e) };
      }
      setRows((prev) => {
        const next = prev.slice();
        next[i] = {
          name: cases[i]!.name,
          state: result.pass
            ? { status: 'pass' }
            : { status: 'fail', detail: result.detail },
        };
        return next;
      });
    }
    setRunning(false);
  }, [group]);

  useEffect(() => {
    run();
    return () => {
      cancelRef.current = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [group.id]);

  const passed = rows.filter((r) => r.state.status === 'pass').length;
  const failed = rows.filter((r) => r.state.status === 'fail').length;
  const total = rows.length;
  const summary =
    total === 0
      ? loading
        ? 'Building…'
        : ''
      : running
        ? `${passed} ✓  ${failed} ✗  · running ${passed + failed}/${total}`
        : failed === 0
          ? `ALL ${total} PASSED`
          : `${passed}/${total} passed · ${failed} FAILED`;

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Pressable style={styles.back} onPress={onBack}>
          <Text style={styles.backText}>‹ Back</Text>
        </Pressable>
        <View style={styles.headerCenter}>
          <Text style={styles.title}>{group.title}</Text>
          {group.description && (
            <Text style={styles.subtitle}>{group.description}</Text>
          )}
        </View>
        <Pressable
          style={[styles.rerun, running && styles.rerunDisabled]}
          onPress={running ? undefined : run}
          disabled={running}
        >
          <Text style={styles.rerunText}>{running ? '…' : 'Re-run'}</Text>
        </Pressable>
      </View>

      {summary !== '' && (
        <Text
          style={[
            styles.summary,
            failed > 0
              ? styles.summaryFail
              : !running && total > 0 && styles.summaryPass,
          ]}
        >
          {summary}
        </Text>
      )}

      {error && <Text style={styles.error}>Fatal: {error}</Text>}

      {loading ? (
        <View style={styles.center}>
          <ActivityIndicator />
        </View>
      ) : (
        <ScrollView contentContainerStyle={styles.list}>
          {rows.map((r, i) => (
            <View key={i} style={styles.row}>
              <View style={styles.tag}>
                <Text style={tagStyleFor(r.state.status)}>
                  {tagTextFor(r.state.status)}
                </Text>
              </View>
              <View style={styles.info}>
                <Text style={styles.name}>{r.name}</Text>
                {r.state.status === 'fail' && r.state.detail && (
                  <Text style={styles.detail}>{r.state.detail}</Text>
                )}
              </View>
            </View>
          ))}
        </ScrollView>
      )}
    </View>
  );
}

function tagTextFor(status: RowState['status']): string {
  switch (status) {
    case 'pending':
      return '·';
    case 'running':
      return '…';
    case 'pass':
      return 'PASS';
    case 'fail':
      return 'FAIL';
  }
}

function tagStyleFor(status: RowState['status']) {
  switch (status) {
    case 'pending':
      return styles.tagPending;
    case 'running':
      return styles.tagRunning;
    case 'pass':
      return styles.tagPass;
    case 'fail':
      return styles.tagFail;
  }
}

const styles = StyleSheet.create({
  container: { flex: 1, paddingTop: 54 },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingBottom: 8,
    gap: 8,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  back: { paddingVertical: 4, paddingHorizontal: 4 },
  backText: { color: '#007AFF', fontSize: 16, fontWeight: '500' },
  headerCenter: { flex: 1, alignItems: 'flex-start' },
  title: { fontSize: 16, fontWeight: '700' },
  subtitle: { fontSize: 11, color: '#666', marginTop: 1 },
  rerun: {
    paddingVertical: 6,
    paddingHorizontal: 12,
    backgroundColor: '#007AFF',
    borderRadius: 6,
  },
  rerunDisabled: { opacity: 0.4 },
  rerunText: { color: '#fff', fontWeight: '600', fontSize: 13 },

  summary: {
    fontSize: 13,
    fontWeight: '600',
    paddingVertical: 8,
    paddingHorizontal: 16,
    textAlign: 'center',
    color: '#333',
  },
  summaryPass: { color: '#1a7d1a' },
  summaryFail: { color: '#c00' },

  error: { color: '#c00', padding: 12, fontSize: 13 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center' },

  list: { paddingHorizontal: 12, paddingBottom: 32 },
  row: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    paddingVertical: 4,
    gap: 8,
  },
  tag: { width: 44, alignItems: 'flex-start', paddingTop: 1 },
  tagPending: { color: '#bbb', fontWeight: '700', fontSize: 12 },
  tagRunning: { color: '#888', fontWeight: '700', fontSize: 12 },
  tagPass: { color: '#1a7d1a', fontWeight: '700', fontSize: 11 },
  tagFail: { color: '#c00', fontWeight: '700', fontSize: 11 },

  info: { flex: 1 },
  name: { fontSize: 12, fontFamily: 'Courier' },
  detail: {
    fontSize: 10,
    fontFamily: 'Courier',
    color: '#888',
    marginTop: 2,
  },
});

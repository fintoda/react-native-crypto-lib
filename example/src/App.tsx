// Stack-style navigation without `react-navigation`: a single state machine
// (`screen`, `groupId`) drives which view is rendered. Hardware back on
// Android pops the stack to the menu.

import { useCallback, useEffect, useState } from 'react';
import { BackHandler, Pressable, StyleSheet, Text, View } from 'react-native';
import MenuScreen from './MenuScreen';
import TestGroupScreen from './TestGroupScreen';
import Demo from './Demo';
import Biometric from './Biometric';
import { TEST_GROUPS, type TestGroup } from './tests';

type Screen =
  | { name: 'menu' }
  | { name: 'group'; groupId: string }
  | { name: 'demo' }
  | { name: 'biometric' };

export default function App() {
  const [screen, setScreen] = useState<Screen>({ name: 'menu' });

  const goHome = useCallback(() => setScreen({ name: 'menu' }), []);

  // Android hardware back: pop to the menu when we're not already there.
  useEffect(() => {
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      if (screen.name === 'menu') return false;
      goHome();
      return true;
    });
    return () => sub.remove();
  }, [screen.name, goHome]);

  if (screen.name === 'menu') {
    return (
      <MenuScreen
        onSelect={(id) => {
          if (id === 'demo') {
            setScreen({ name: 'demo' });
            return;
          }
          if (id === 'biometric') {
            setScreen({ name: 'biometric' });
            return;
          }
          setScreen({ name: 'group', groupId: id });
        }}
      />
    );
  }

  if (screen.name === 'demo') {
    return (
      <ScreenWithBack title="Usage demos" onBack={goHome}>
        <Demo />
      </ScreenWithBack>
    );
  }

  if (screen.name === 'biometric') {
    return (
      <ScreenWithBack title="Biometric (interactive)" onBack={goHome}>
        <Biometric />
      </ScreenWithBack>
    );
  }

  // group
  const group: TestGroup | undefined = TEST_GROUPS.find(
    (g) => g.id === screen.groupId
  );
  if (!group) {
    return (
      <ScreenWithBack title="Unknown" onBack={goHome}>
        <View style={styles.fallback}>
          <Text>Unknown group: {screen.groupId}</Text>
        </View>
      </ScreenWithBack>
    );
  }
  return <TestGroupScreen group={group} onBack={goHome} />;
}

function ScreenWithBack({
  title,
  onBack,
  children,
}: {
  title: string;
  onBack: () => void;
  children: React.ReactNode;
}) {
  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Pressable style={styles.back} onPress={onBack}>
          <Text style={styles.backText}>‹ Back</Text>
        </Pressable>
        <Text style={styles.headerTitle}>{title}</Text>
        <View style={styles.spacer} />
      </View>
      <View style={styles.body}>{children}</View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, paddingTop: 54 },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingBottom: 8,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  back: { paddingVertical: 4, paddingHorizontal: 4 },
  backText: { color: '#007AFF', fontSize: 16, fontWeight: '500' },
  headerTitle: {
    flex: 1,
    textAlign: 'center',
    fontWeight: '700',
    fontSize: 16,
  },
  spacer: { width: 60 },
  body: { flex: 1 },
  fallback: { flex: 1, alignItems: 'center', justifyContent: 'center' },
});

/**
 * Post-codegen patch: wraps target_compile_reactnative_options() in a
 * compatibility guard so the generated CMakeLists.txt works on RN < 0.80
 * where this CMake function doesn't exist yet.
 */

const fs = require('fs');
const path = require('path');

const file = path.join(
  __dirname,
  '..',
  'android',
  'generated',
  'jni',
  'CMakeLists.txt'
);

if (!fs.existsSync(file)) {
  process.exit(0);
}

const content = fs.readFileSync(file, 'utf8');

if (content.includes('if(COMMAND target_compile_reactnative_options)')) {
  process.exit(0);
}

const patched = content.replace(
  /^(target_compile_reactnative_options\(.+\))$/m,
  'if(COMMAND target_compile_reactnative_options)\n  $1\nendif()'
);

fs.writeFileSync(file, patched);

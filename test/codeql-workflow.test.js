import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workflow = readFileSync(new URL('../.github/workflows/codeql.yml', import.meta.url), 'utf8');

test('CodeQL preserves the main baseline configuration during per-language migration', () => {
  assert.match(workflow, /jobs:\s*\n\s+analyze:\s*\n\s+name:\s*Analyze baseline compatibility/);
  assert.match(workflow, /analyze:[\s\S]*?languages:\s*javascript-typescript,\s*python/);
  assert.match(workflow, /analyze_by_language:/);
});

test('CodeQL publishes stable per-language configurations for PR comparison', () => {
  assert.match(workflow, /analyze_by_language:[\s\S]*?strategy:\s*\n\s+fail-fast:\s*false\s*\n\s+max-parallel:\s*2\s*\n\s+matrix:\s*\n\s+language:\s*\[javascript-typescript, python\]/);
  assert.match(workflow, /languages:\s*\$\{\{ matrix\.language \}\}/);
  assert.match(workflow, /category:\s*["']?\/language:\$\{\{ matrix\.language \}\}["']?/);
});

test('CodeQL migration jobs stay bounded to Ubuntu', () => {
  assert.match(workflow, /runs-on:\s*ubuntu-latest/);
  assert.match(workflow, /timeout-minutes:\s*15/);
  assert.match(workflow, /max-parallel:\s*2/);
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
  assert.doesNotMatch(workflow, /macos-latest|windows-latest/);
});

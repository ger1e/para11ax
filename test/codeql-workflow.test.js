import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workflow = readFileSync(new URL('../.github/workflows/codeql.yml', import.meta.url), 'utf8');

test('CodeQL publishes stable per-language configurations for PR comparison', () => {
  assert.match(workflow, /strategy:\s*\n\s+fail-fast:\s*false\s*\n\s+matrix:\s*\n\s+language:\s*\[javascript-typescript, python\]/);
  assert.match(workflow, /languages:\s*\$\{\{ matrix\.language \}\}/);
  assert.match(workflow, /category:\s*["']?\/language:\$\{\{ matrix\.language \}\}["']?/);
  assert.doesNotMatch(workflow, /languages:\s*javascript-typescript,\s*python/);
});

test('CodeQL keeps one bounded Ubuntu job per configured language', () => {
  assert.match(workflow, /runs-on:\s*ubuntu-latest/);
  assert.match(workflow, /timeout-minutes:\s*15/);
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
  assert.doesNotMatch(workflow, /macos-latest|windows-latest/);
});

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import browserConfig from '../playwright.config.mjs';

test('browser smoke serializes full audiovisual boots within a bounded timeout', () => {
  assert.equal(browserConfig.fullyParallel, false);
  assert.equal(browserConfig.workers, 1);
  assert.equal(browserConfig.timeout, 60_000);
  assert.equal(browserConfig.expect?.timeout, 45_000);
});

test('browser smoke advances intentional boot delays with the browser clock', () => {
  const spec = readFileSync(new URL('../browser-tests/initialize.spec.mjs', import.meta.url), 'utf8');
  assert.match(spec, /await page\.clock\.install\(\)/);
  assert.match(spec, /await page\.clock\.runFor\(20_000\)/);
  assert.match(spec, /const snapshot = await page\.evaluate/);
  assert.doesNotMatch(spec, /const body = page\.locator/);
});

test('browser smoke command exposes desktop and reduced-motion mobile Initialize coverage', () => {
  const result = spawnSync('npm', ['run', 'test:browser', '--', '--list'], {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
  });
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;

  assert.equal(result.status, 0, output);
  assert.match(output, /\[desktop\].*Initialize.*normal motion/i);
  assert.match(output, /\[mobile-reduced\].*Initialize.*reduced motion/i);
  assert.match(output, /Total:\s+2 tests? in 1 file/i);
});

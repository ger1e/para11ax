import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

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

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const config = await readFile(new URL('../.github/dependabot.yml', import.meta.url), 'utf8');
const toolingWorkflow = await readFile(new URL('../.github/workflows/tooling-smoke.yml', import.meta.url), 'utf8');

function updateBlocks(source) {
  return source
    .split(/^  - package-ecosystem:/m)
    .slice(1)
    .map(block => `  - package-ecosystem:${block}`);
}

function value(block, key) {
  return block.match(new RegExp(`^ {2,4}(?:- )?${key}: ["']?([^"'\\n]+)["']?$`, 'm'))?.[1]?.trim();
}

test('Dependabot covers every committed Python requirements surface', () => {
  const pipDirectories = updateBlocks(config)
    .filter(block => value(block, 'package-ecosystem') === 'pip')
    .map(block => value(block, 'directory'))
    .sort();

  assert.deepEqual(pipDirectories, ['/maltego', '/workers/user-scanner']);
});

test('Tooling smoke installs and checks every committed Python requirements surface', () => {
  assert.match(toolingWorkflow, /pip install[^\n]+maltego\/requirements\.txt/);
  assert.match(toolingWorkflow, /pip install[^\n]+workers\/user-scanner\/requirements\.txt/);
  assert.match(toolingWorkflow, /import maltego_trx/);
  assert.match(toolingWorkflow, /import jwt; import worker/);
  assert.equal(toolingWorkflow.match(/pip check/g)?.length, 2);
});

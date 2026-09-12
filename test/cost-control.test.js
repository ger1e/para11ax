import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workflow = readFileSync(new URL('../.github/workflows/tooling-smoke.yml', import.meta.url), 'utf8');
const vercel = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8'));

test('public hosted CI runs only for pull requests to main, pushes to main, or manual dispatch', () => {
  assert.match(workflow, /on:\s*\n\s*workflow_dispatch:/);
  assert.match(workflow, /^\s+pull_request:\s*$/m);
  assert.match(workflow, /pull_request:\s*\n\s+branches:\s*\n\s+- main/);
  assert.match(workflow, /^\s+push:\s*$/m);
  assert.match(workflow, /push:\s*\n\s+branches:\s*\n\s+- main/);
  assert.doesNotMatch(workflow, /^\s+schedule:/m);
  assert.doesNotMatch(workflow, /^\s+workflow_run:/m);
  assert.doesNotMatch(workflow, /^\s+repository_dispatch:/m);
});

test('hosted CI is bounded to one validation runner plus one lightweight status publisher', () => {
  const runners = [...workflow.matchAll(/^\s+runs-on:\s*([^\n]+)/gm)].map(match => match[1].trim());
  assert.deepEqual(runners, ['ubuntu-latest', 'ubuntu-latest']);
  assert.match(workflow, /\n  validate:\n/);
  assert.match(workflow, /\n  publish_status:\n/);
  assert.match(workflow, /publish_status:[\s\S]*?needs: validate/);
  assert.match(workflow, /publish_status:[\s\S]*?timeout-minutes: 2/);
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
  assert.doesNotMatch(workflow, /apt-get|brew\s+install|winget\s+install/i);
  assert.match(workflow, /validate:[\s\S]*?timeout-minutes: 10/);
  assert.match(workflow, /cancel-in-progress: true/);

  const publisher = workflow.slice(workflow.indexOf('\n  publish_status:\n'));
  assert.doesNotMatch(publisher, /actions\/checkout|setup-node|npm\s|python3\s+-m|shellcheck|pwsh/);
});

test('automatic Vercel Git deployment is limited to protected main including slash branches', () => {
  assert.deepEqual(vercel?.git?.deploymentEnabled, {
    '**': false,
    main: true,
  });
});

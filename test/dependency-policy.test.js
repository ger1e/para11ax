import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const text = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const json = path => JSON.parse(text(path));
const approvedDevDependencies = Object.freeze({ '@playwright/test': '1.63.0' });

test('npm dependency state keeps runtime empty and pins only the browser QA toolchain', () => {
  const pkg = json('package.json');
  const lock = json('package-lock.json');
  assert.equal(lock.lockfileVersion, 3);
  assert.equal(lock.name, pkg.name);
  assert.equal(lock.version, pkg.version);
  assert.deepEqual(pkg.dependencies ?? {}, {});
  assert.deepEqual(pkg.devDependencies ?? {}, approvedDevDependencies);
  assert.deepEqual(lock.packages?.['']?.dependencies ?? {}, {});
  assert.deepEqual(lock.packages?.['']?.devDependencies ?? {}, approvedDevDependencies);
  assert.equal(lock.packages?.['node_modules/@playwright/test']?.version, '1.63.0');
});

test('CI performs deterministic install and a real npm audit against the committed lockfile', () => {
  const workflow = text('.github/workflows/tooling-smoke.yml');
  assert.match(workflow, /npm ci --ignore-scripts/);
  assert.match(workflow, /npm audit --omit=dev/);
});

test('repository verification treats a missing lockfile as a hard failure rather than an audit skip', () => {
  const verify = text('scripts/verify-repo.sh');
  assert.match(verify, /package-lock\.json/);
  assert.doesNotMatch(verify, /dependency audit skipped \(no locked npm dependency set\)/i);
  const pkg = json('package.json');
  assert.match(pkg.scripts?.['verify:deps'] ?? '', /npm ci --ignore-scripts/);
  assert.match(pkg.scripts?.['verify:deps'] ?? '', /npm audit --omit=dev/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { COMMAND_REGISTRY } from '../app/shell-core/catalog.js';
import { executeMissionCommand } from '../src/core/mission/command-adapter.js';
import { importMissionWorkspace } from '../src/core/mission/workspace.js';

const text = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

const missionSources = Object.freeze([
  'src/core/mission/workspace.js',
  'src/core/mission/command-adapter.js',
  'src/control/mission-content-loader.js',
  'app/mission-file-bridge.js',
]);

function collectKeys(value, keys = []) {
  if (!value || typeof value !== 'object') return keys;
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, keys);
    return keys;
  }
  for (const [key, nested] of Object.entries(value)) {
    keys.push(key);
    collectKeys(nested, keys);
  }
  return keys;
}

test('mission workspace implementation adds no network secret persistence or execution primitive', () => {
  for (const path of missionSources) {
    const source = text(path);
    assert.doesNotMatch(source, /\bfetch\s*\(|XMLHttpRequest|WebSocket\s*\(/, `${path}: network`);
    assert.doesNotMatch(source, /process\.env|Authorization|PARA11AX_TOKEN|document\.cookie/i, `${path}: secrets`);
    assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|caches\.open/, `${path}: persistence`);
    assert.doesNotMatch(source, /child_process|\beval\s*\(|new\s+Function\s*\(/, `${path}: execution`);
  }
});

test('every mission command is no-egress no-auth and capability-free', () => {
  const descriptors = COMMAND_REGISTRY.byNamespace('mission');
  assert.equal(descriptors.length, 12);
  for (const descriptor of descriptors) {
    assert.equal(descriptor.egressClass, 'none', descriptor.id);
    assert.equal(descriptor.auth, 'none', descriptor.id);
    assert.deepEqual(descriptor.capabilities, [], descriptor.id);
    assert.notEqual(descriptor.sideEffect, 'filesystem', descriptor.id);
    assert.notEqual(descriptor.sideEffect, 'network', descriptor.id);
  }
});

test('portable mission exports contain data only and no secret-shaped keys', async () => {
  const created = await executeMissionCommand({ handler: 'mission-new' });
  const exported = await executeMissionCommand({ handler: 'mission-export', workspace: created.workspace });
  const artifact = exported.output.value;
  assert.deepEqual(Object.keys(artifact).sort(), ['content', 'encoding', 'filename', 'mimeType']);
  assert.equal(typeof artifact.content, 'string');

  const bundle = importMissionWorkspace(artifact.content);
  const keys = collectKeys(bundle).map(key => key.toLowerCase());
  for (const forbidden of ['token', 'authorization', 'cookie', 'password', 'apikey', 'api_key']) {
    assert.equal(keys.includes(forbidden), false, forbidden);
  }
  assert.doesNotMatch(artifact.content, /bearer\s+[a-z0-9._~-]+/i);
});

test('mission workspace keeps runtime dependencies empty and preserves the browser QA allowlist', () => {
  const pkg = JSON.parse(text('package.json'));
  const lock = JSON.parse(text('package-lock.json'));
  const approvedDevDependencies = { '@playwright/test': '1.63.0' };
  assert.deepEqual(pkg.dependencies ?? {}, {});
  assert.deepEqual(pkg.devDependencies ?? {}, approvedDevDependencies);
  assert.deepEqual(lock.packages?.['']?.dependencies ?? {}, {});
  assert.deepEqual(lock.packages?.['']?.devDependencies ?? {}, approvedDevDependencies);
});

import test from 'node:test';
import assert from 'node:assert/strict';

import { COMMAND_REGISTRY } from '../app/shell-core/catalog.js';

const EXPECTED = Object.freeze([
  ['domain-investigation', 'build'],
  ['domain-investigation', 'surface-import'],
  ['domain-investigation', 'vulnerability-import'],
  ['domain-investigation', 'show'],
  ['domain-investigation', 'report'],
  ['domain-investigation', 'stix'],
  ['domain-investigation', 'handoff'],
  ['domain-investigation', 'clear'],
]);

test('Domain Investigation shell commands are registered on CLI with bounded local semantics', () => {
  for (const tokens of EXPECTED) {
    const resolved = COMMAND_REGISTRY.resolve(tokens, 'cli');
    assert.ok(resolved, `${tokens.join(' ')} must resolve on CLI`);
    assert.equal(resolved.descriptor.namespace, 'domain-investigation');
    assert.equal(resolved.descriptor.egressClass, 'none');
    assert.equal(resolved.descriptor.auth, 'none');
    assert.ok(resolved.descriptor.handler.startsWith('domain-investigation-'));
  }
});

test('Domain Investigation build/import commands accept explicit content transports, never scanner/provider capability', () => {
  for (const tokens of [EXPECTED[0], EXPECTED[1], EXPECTED[2]]) {
    const resolved = COMMAND_REGISTRY.resolve(tokens, 'cli');
    assert.ok(resolved);
    assert.deepEqual(resolved.descriptor.capabilities, []);
    assert.equal(resolved.descriptor.sideEffect, 'session');
  }
});

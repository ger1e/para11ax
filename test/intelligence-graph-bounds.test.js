import test from 'node:test';
import assert from 'node:assert/strict';
import { buildEvidenceGraph } from '../src/core/evidence-graph.js';

function graph(relationships, options = {}) {
  return buildEvidenceGraph({ indicator: 'example.com', type: 'domain', evidence: [], relationships, correlation: {}, decision: {}, ...options });
}

test('graph rejects markup-bearing observable relationship targets', () => {
  const output = graph([{ type: 'related_to', targetType: 'domain', target: '<mark>example.net</mark>', provider: 'fixture' }]);
  assert.equal(output.nodes.some(node => String(node.value ?? '').includes('<')), false);
  assert.equal(output.edges.length, 0);
});

test('duplicate relationship edges collapse by stable identity', () => {
  const relation = { type: 'resolves_to', targetType: 'ip', target: '192.0.2.10', provider: 'fixture' };
  const output = graph([relation, { ...relation }]);
  assert.equal(output.edges.length, 1);
  assert.equal(output.nodes.filter(node => node.type === 'observable').length, 2);
});

test('configured relationship expansion stops at its explicit bound', () => {
  const output = graph([
    { type: 'resolves_to', targetType: 'ip', target: '192.0.2.10', provider: 'fixture' },
    { type: 'resolves_to', targetType: 'ip', target: '192.0.2.11', provider: 'fixture' },
  ], { maxRelationships: 1 });
  assert.equal(output.edges.length, 1);
  assert.equal(output.truncated, true);
});

test('invalid graph bounds fail closed', () => {
  assert.throws(() => graph([], { maxRelationships: 0 }), /relationship_limit/);
  assert.throws(() => graph([], { maxRelationships: 513 }), /relationship_limit/);
});

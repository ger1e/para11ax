import test from 'node:test';
import assert from 'node:assert/strict';
import { d3fendProvider } from '../src/providers/d3fend.js';
import { evidenceRole } from '../src/core/evidence-semantics.js';

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

const FIXTURE = {
  off_to_def: {
    results: {
      bindings: [
        {
          off_tech_label: { value: 'Command and Scripting Interpreter' },
          def_tech_id: { value: 'D3-SCA' },
          def_tech_label: { value: 'Script Execution Analysis' },
          def_tactic_label: { value: 'Detect' },
        },
        {
          off_tech_label: { value: 'Command and Scripting Interpreter' },
          def_tech_id: { value: 'D3-SCA' },
          def_tech_label: { value: 'Script Execution Analysis' },
          def_tactic_label: { value: 'Detect' },
        },
        {
          off_tech_label: { value: 'Command and Scripting Interpreter' },
          def_tech_id: { value: 'D3-AL' },
          def_tech_label: { value: 'Executable Allowlisting' },
          def_tactic_label: { value: 'Isolate' },
        },
      ],
    },
  },
  description: { '@graph': [] },
  subtechniques: { '@graph': [] },
};

test('D3FEND performs one fixed ATT&CK-to-defensive-knowledge lookup', async () => {
  const calls = [];
  const out = await d3fendProvider.run({ type: 'attack', value: 'T1059' }, {
    fetchImpl: async (url, options) => {
      calls.push([String(url), options]);
      return jsonResponse(FIXTURE);
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'https://d3fend.mitre.org/api/offensive-technique/attack/T1059.json');
  assert.equal(calls[0][1].method, 'GET');
  assert.equal(out.observationType, 'defensive_knowledge');
  assert.equal(out.verdict, 'reference');
  assert.equal(out.attributes.attackId, 'T1059');
  assert.equal(out.attributes.attackTechnique, 'Command and Scripting Interpreter');
  assert.deepEqual(out.attributes.defensiveTechniques, [
    { id: 'D3-AL', label: 'Executable Allowlisting', tactic: 'Isolate' },
    { id: 'D3-SCA', label: 'Script Execution Analysis', tactic: 'Detect' },
  ]);
  assert.deepEqual(out.relationships, []);
});

test('D3FEND knowledge is semantically isolated from threat polarity', () => {
  assert.equal(evidenceRole({ semanticClass: 'defensive_knowledge', sourceRole: 'first_party' }), 'knowledge_only');
});

test('D3FEND empty mappings are neutral absence and malformed success fails closed', async () => {
  const empty = await d3fendProvider.run({ type: 'attack', value: 'T1059' }, {
    fetchImpl: async () => jsonResponse({ off_to_def: { results: { bindings: [] } }, description: { '@graph': [] }, subtechniques: { '@graph': [] } }),
  });
  assert.equal(empty.verdict, 'not_found');
  await assert.rejects(
    () => d3fendProvider.run({ type: 'attack', value: 'T1059' }, { fetchImpl: async () => jsonResponse({ off_to_def: { results: { bindings: 'oops' } } }) }),
    /provider_schema_invalid/,
  );
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  derivePromotionCandidates,
  createPromotionState,
  applyPromotionEvent,
  deriveEffectiveAttestations,
} from '../src/core/evidence-promotion.js';

const source = (overrides = {}) => ({
  id: 'SURF-ABC123',
  kind: 'authorized_surface_finding',
  capturedAt: '2026-09-13T12:00:00.000Z',
  source: 'authorized-discovery',
  summary: 'Observed suspicious.example resolving to 203.0.113.10.',
  references: ['https://scanner.invalid/run/1'],
  observable: { type: 'domain', value: 'suspicious.example' },
  observation: { kind: 'operator_finding', verdict: 'suspicious' },
  ...overrides,
});

const approve = (candidateId, overrides = {}) => ({
  type: 'approved',
  candidateId,
  at: '2026-09-13T13:00:00.000Z',
  actorLabel: 'analyst:g',
  reason: 'Validated against authorized investigation context.',
  ...overrides,
});

test('promotion candidates are deterministic and have zero authority', () => {
  const a = source();
  const b = source({ id: 'VULN-DEF456', observable: { type: 'cve', value: 'CVE-2026-12345' }, references: ['https://scanner.invalid/run/2'] });
  const left = derivePromotionCandidates([a, b]);
  const right = derivePromotionCandidates([b, a]);
  assert.deepEqual(left, right);
  assert.equal(left.length, 2);
  assert.ok(left.every(item => item.status === 'candidate'));
  assert.ok(left.every(item => item.authority === undefined));
  assert.ok(left.every(item => /^[a-f0-9]{64}$/.test(item.fingerprint)));
});

test('approval creates immutable analyst attestation with intact provenance', () => {
  const state = createPromotionState([source()]);
  const candidate = state.candidates[0];
  const approved = applyPromotionEvent(state, approve(candidate.id));
  const effective = deriveEffectiveAttestations(approved.candidates, approved.events);
  assert.equal(state.events.length, 0);
  assert.equal(approved.events.length, 1);
  assert.equal(effective.length, 1);
  const attestation = effective[0];
  assert.equal(attestation.sourceArtifactId, 'SURF-ABC123');
  assert.deepEqual(attestation.observable, { type: 'domain', value: 'suspicious.example' });
  assert.equal(attestation.authority, 'analyst_promoted');
  assert.equal(attestation.authorityClass, 'analyst_attestation');
  assert.equal(attestation.actorLabel, 'analyst:g');
  assert.deepEqual(attestation.references, ['https://scanner.invalid/run/1']);
  assert.equal(Object.isFrozen(attestation), true);
});

test('rejection has no authority and blocks later approval of the same candidate', () => {
  const state = createPromotionState([source()]);
  const id = state.candidates[0].id;
  const rejected = applyPromotionEvent(state, { ...approve(id), type: 'rejected' });
  assert.deepEqual(deriveEffectiveAttestations(rejected.candidates, rejected.events), []);
  assert.throws(() => applyPromotionEvent(rejected, approve(id, { at: '2026-09-13T14:00:00.000Z' })), /rejected|transition/i);
});

test('revocation removes effective corroboration but preserves audit history', () => {
  let state = createPromotionState([source()]);
  const id = state.candidates[0].id;
  state = applyPromotionEvent(state, approve(id));
  const [attestation] = deriveEffectiveAttestations(state.candidates, state.events);
  state = applyPromotionEvent(state, {
    type: 'revoked', attestationId: attestation.id, at: '2026-09-13T14:00:00.000Z', actorLabel: 'analyst:g', reason: 'Later validation disproved the finding.',
  });
  assert.equal(state.events.length, 2);
  assert.deepEqual(deriveEffectiveAttestations(state.candidates, state.events), []);
});

test('supersession preserves prior audit and activates one replacement attestation', () => {
  const original = source();
  const replacement = source({
    summary: 'Observed suspicious.example with stronger validated evidence.',
    references: ['https://scanner.invalid/run/3'],
    observation: { kind: 'operator_finding', verdict: 'malicious' },
  });
  let state = createPromotionState([original, replacement]);
  const first = state.candidates.find(c => c.observation.verdict === 'suspicious');
  const second = state.candidates.find(c => c.observation.verdict === 'malicious');
  state = applyPromotionEvent(state, approve(first.id));
  const [oldAttestation] = deriveEffectiveAttestations(state.candidates, state.events);
  state = applyPromotionEvent(state, {
    type: 'superseded', candidateId: second.id, attestationId: oldAttestation.id,
    at: '2026-09-13T14:00:00.000Z', actorLabel: 'analyst:g', reason: 'Materially stronger source artifact claim supersedes the prior attestation.',
  });
  const effective = deriveEffectiveAttestations(state.candidates, state.events);
  assert.equal(state.events.length, 2);
  assert.equal(effective.length, 1);
  assert.equal(effective[0].sourceArtifactId, oldAttestation.sourceArtifactId);
  assert.equal(effective[0].observation.verdict, 'malicious');
  assert.notEqual(effective[0].fingerprint, oldAttestation.fingerprint);
});

test('duplicate approval and recursive promotion fail closed', () => {
  let state = createPromotionState([source()]);
  const id = state.candidates[0].id;
  state = applyPromotionEvent(state, approve(id));
  assert.throws(() => applyPromotionEvent(state, approve(id, { at: '2026-09-13T14:00:00.000Z' })), /active|duplicate|transition/i);
  assert.throws(() => createPromotionState([source({ kind: 'analyst_attestation' })]), /recursive|attestation/i);
});

test('malformed, oversized and unsafe source material is rejected atomically', () => {
  assert.throws(() => createPromotionState([source({ references: ['file:///etc/passwd'] })]), /reference|http/i);
  assert.throws(() => createPromotionState([source({ references: ['https://user:pass@example.com/run'] })]), /credential|reference/i);
  assert.throws(() => createPromotionState([source({ summary: 'api_key=supersecretvalue' })]), /secret|credential/i);
  assert.throws(() => createPromotionState([source({ summary: 'x'.repeat(4097) })]), /4096|limit|length/i);

  const state = createPromotionState([source()]);
  assert.throws(() => applyPromotionEvent(state, { ...approve('missing'), at: '2026-09-13T14:00:00.000Z' }), /candidate/i);
  assert.equal(state.events.length, 0);
});

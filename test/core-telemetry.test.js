import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequestTelemetry } from '../src/core/telemetry.js';

test('request telemetry allowlists safe fields and strips sensitive context', () => {
  let tick = 1700000000000;
  const telemetry = createRequestTelemetry({ maxEvents: 8, now: () => ++tick });

  telemetry.emit('scheduler.provider_attempt', {
    provider: 'example-provider',
    providerFamily: 'example-family',
    attempt: 1,
    phase: 'complete',
    durationMs: 42,
    outcome: 'success',
    status: 200,
    retry: false,
    taskId: 'secret-task-id',
    indicator: '203.0.113.10',
    credentials: { token: 'secret' },
    headers: { authorization: 'Bearer secret' },
    authorization: 'Bearer secret',
    payload: { raw: 'secret' },
    requestBody: 'secret',
    responseBody: 'secret',
    unknownField: 'discard me',
  });

  const [event] = telemetry.events();
  assert.equal(event.name, 'scheduler.provider_attempt');
  assert.equal(event.observedAt, 1700000000001);
  assert.deepEqual(event.fields, {
    provider: 'example-provider',
    providerFamily: 'example-family',
    attempt: 1,
    phase: 'complete',
    durationMs: 42,
    outcome: 'success',
    status: 200,
    retry: false,
  });
  assert.doesNotMatch(JSON.stringify(event), /secret-task-id|203\.0\.113\.10|Bearer secret|discard me/);
});

test('request telemetry is bounded and counts dropped events', () => {
  const telemetry = createRequestTelemetry({ maxEvents: 2, now: () => 1 });
  telemetry.emit('scheduler.provider_attempt', { provider: 'a', outcome: 'success' });
  telemetry.emit('scheduler.provider_attempt', { provider: 'b', outcome: 'failure' });
  telemetry.emit('scheduler.provider_attempt', { provider: 'c', outcome: 'success' });

  assert.equal(telemetry.events().length, 2);
  assert.equal(telemetry.snapshot().droppedEvents, 1);
});

test('snapshot aggregates attempts, outcomes, retries and provider duration', () => {
  const telemetry = createRequestTelemetry({ maxEvents: 8, now: () => 1 });
  telemetry.emit('scheduler.provider_attempt', { provider: 'alpha', providerFamily: 'family-a', attempt: 1, durationMs: 10, outcome: 'retry', retry: true });
  telemetry.emit('scheduler.provider_attempt', { provider: 'alpha', providerFamily: 'family-a', attempt: 2, durationMs: 20, outcome: 'success', status: 200, retry: false });
  telemetry.emit('scheduler.provider_attempt', { provider: 'beta', providerFamily: 'family-b', attempt: 1, durationMs: 5, outcome: 'failure', status: 503, retry: false });

  assert.deepEqual(telemetry.snapshot(), {
    eventCount: 3,
    droppedEvents: 0,
    providerAttempts: 3,
    successes: 1,
    failures: 1,
    retries: 1,
    totalDurationMs: 35,
    maxDurationMs: 20,
    providers: ['alpha', 'beta'],
    providerFamilies: ['family-a', 'family-b'],
    outcomes: { retry: 1, success: 1, failure: 1 },
    statuses: { '200': 1, '503': 1 },
  });
});

test('invalid telemetry inputs are fail-safe', () => {
  const telemetry = createRequestTelemetry({ maxEvents: 4, now: () => 1 });
  assert.doesNotThrow(() => telemetry.emit('', null));
  assert.doesNotThrow(() => telemetry.emit(null, { provider: 'x' }));
  assert.equal(telemetry.events().length, 0);
});

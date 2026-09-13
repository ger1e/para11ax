import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyIntelligenceIndicator } from '../src/core/intelligence-observables.js';
import { intelligenceObservableTypes } from '../src/core/intelligence-observable-registry.js';
import { observableTypes } from '../src/core/observable-registry.js';

test('classifies new intelligence observable classes explicitly', () => {
  assert.deepEqual(classifyIntelligenceIndicator('analyst@example.com'), { value: 'analyst@example.com', type: 'email' });
  assert.deepEqual(classifyIntelligenceIndicator('pkg:npm/%40scope/name@1.2.3'), { value: 'pkg:npm/%40scope/name@1.2.3', type: 'package' });
  assert.deepEqual(classifyIntelligenceIndicator('ja3:72a589da586844d7f0818ce684948eea'), { value: 'ja3:72a589da586844d7f0818ce684948eea', type: 'tls-fingerprint' });
  assert.deepEqual(classifyIntelligenceIndicator('btc:1BoatSLRHtKNngkdXEeobR76b53LETtpyT'), { value: 'btc:1BoatSLRHtKNngkdXEeobR76b53LETtpyT', type: 'crypto-address' });
  assert.deepEqual(classifyIntelligenceIndicator(`hmsl-sha256:${'a'.repeat(64)}`), { value: `hmsl-sha256:${'a'.repeat(64)}`, type: 'secret-fingerprint' });
  assert.deepEqual(classifyIntelligenceIndicator('entity:5493001KJTIIGC8Y1R12'), { value: 'entity:5493001KJTIIGC8Y1R12', type: 'legal-entity' });
  assert.deepEqual(classifyIntelligenceIndicator('user:para11ax_qa'), { value: 'para11ax_qa', type: 'username' });
});

test('TLS fingerprints require an explicit supported family', () => {
  assert.deepEqual(classifyIntelligenceIndicator('JA4:t13d1516h2_8daaf6152771_02713d6af862'), {
    value: 'ja4:t13d1516h2_8daaf6152771_02713d6af862',
    type: 'tls-fingerprint',
  });
  assert.throws(() => classifyIntelligenceIndicator('ja3:not-a-hash'), /unsupported indicator/);
});

test('crypto addresses require an explicit supported network prefix while legacy hash identity remains stable', () => {
  assert.deepEqual(classifyIntelligenceIndicator('eth:52908400098527886E0F7030069857D2E4169EE7'), {
    value: 'eth:52908400098527886e0f7030069857d2e4169ee7',
    type: 'crypto-address',
  });
  assert.deepEqual(classifyIntelligenceIndicator('52908400098527886E0F7030069857D2E4169EE7'), {
    value: '52908400098527886e0f7030069857d2e4169ee7',
    type: 'hash',
  });
});

test('rejects malformed explicit new observable forms', () => {
  for (const value of [
    'not an email@example.com','pkg:npm','user:two words','entity:not-valid',
    'btc:not-an-address','eth:1234','hmsl-sha256:not-a-digest',
  ]) assert.throws(() => classifyIntelligenceIndicator(value), /unsupported indicator/);
});

test('intelligence registry extends rather than mutates the nine-type v8 registry', () => {
  assert.equal(observableTypes().length, 9);
  const types = new Set(intelligenceObservableTypes());
  assert.equal(types.size, 16);
  for (const type of ['email','package','tls-fingerprint','crypto-address','secret-fingerprint','legal-entity','username']) {
    assert.equal(types.has(type), true, type);
  }
});

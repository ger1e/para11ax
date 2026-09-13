import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyIndicator } from '../src/core/validate.js';
import { observableTypes } from '../src/core/observable-registry.js';

test('classifies new intelligence observable classes explicitly', () => {
  assert.deepEqual(classifyIndicator('analyst@example.com'), { value: 'analyst@example.com', type: 'email' });
  assert.deepEqual(classifyIndicator('pkg:npm/%40scope/name@1.2.3'), { value: 'pkg:npm/%40scope/name@1.2.3', type: 'package' });
  assert.deepEqual(classifyIndicator('ja3:72a589da586844d7f0818ce684948eea'), { value: 'ja3:72a589da586844d7f0818ce684948eea', type: 'tls-fingerprint' });
  assert.deepEqual(classifyIndicator('btc:1BoatSLRHtKNngkdXEeobR76b53LETtpyT'), { value: 'btc:1BoatSLRHtKNngkdXEeobR76b53LETtpyT', type: 'crypto-address' });
  assert.deepEqual(classifyIndicator(`hmsl-sha256:${'a'.repeat(64)}`), { value: `hmsl-sha256:${'a'.repeat(64)}`, type: 'secret-fingerprint' });
  assert.deepEqual(classifyIndicator('entity:5493001KJTIIGC8Y1R12'), { value: 'entity:5493001KJTIIGC8Y1R12', type: 'legal-entity' });
  assert.deepEqual(classifyIndicator('user:para11ax_qa'), { value: 'para11ax_qa', type: 'username' });
});

test('TLS fingerprints require an explicit supported family', () => {
  assert.deepEqual(classifyIndicator('JA4:t13d1516h2_8daaf6152771_02713d6af862'), {
    value: 'ja4:t13d1516h2_8daaf6152771_02713d6af862',
    type: 'tls-fingerprint',
  });
  assert.throws(() => classifyIndicator('ja3:not-a-hash'), /unsupported indicator/);
});

test('crypto addresses require an explicit supported network prefix', () => {
  assert.deepEqual(classifyIndicator('eth:52908400098527886E0F7030069857D2E4169EE7'), {
    value: 'eth:52908400098527886e0f7030069857d2e4169ee7',
    type: 'crypto-address',
  });
  assert.throws(() => classifyIndicator('52908400098527886E0F7030069857D2E4169EE7'), /unsupported indicator/);
});

test('rejects ambiguous new observable forms', () => {
  for (const value of [
    'not an email@example.com','pkg:npm','para11ax_qa','user:two words','entity:not-valid',
    'btc:not-an-address','eth:1234','hmsl-sha256:not-a-digest',
  ]) assert.throws(() => classifyIndicator(value), /unsupported indicator/);
});

test('observable registry includes explicit new types', () => {
  const types = new Set(observableTypes());
  for (const type of ['email','package','tls-fingerprint','crypto-address','secret-fingerprint','legal-entity','username']) {
    assert.equal(types.has(type), true, type);
  }
});

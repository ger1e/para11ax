import test from 'node:test';
import assert from 'node:assert/strict';
import { toStixBundle, uuidV5 } from '../src/export/stix.js';
import { createApp } from '../src/app.js';

test('emits standard UUIDv5 identities without runtime-specific crypto', () => {
  assert.equal(
    uuidV5('www.widgets.com', '6ba7b810-9dad-11d1-80b4-00c04fd430c8'),
    '21f7f8de-8051-5b89-8680-0195ef798b6a',
  );
});

const UUIDS = [
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '33333333-3333-4333-8333-333333333333',
  '44444444-4444-4444-8444-444444444444',
];

function uuid() { return UUIDS.shift() ?? '55555555-5555-4555-8555-555555555555'; }
function enrichment(indicator, type, evidence = [], relationships = []) {
  return { schemaVersion: '2.0.0', gatewayVersion: '2.0.0', requestId: 'r', indicator, type, queriedAt: '2026-08-21T01:00:00.000Z', status: 'ok', evidence, relationships };
}
function ev(provider, kind, attributes = {}, references = []) {
  return { provider, indicator: 'x', type: 'x', observation: { kind, verdict: 'unknown', confidence: null, firstSeen: null, lastSeen: null, tags: [], malwareFamily: null, actor: null, attributes }, relationships: [], references, retrievedAt: '2026-08-21T00:00:00Z', integrity: { parserVersion: '1', fingerprint: 'a'.repeat(64), rawHash: null } };
}

test('STIX bundle emits defensible IOC patterns for IP domain URL hash and ASN', () => {
  const cases = [
    ['192.0.2.44', 'ip', "[ipv4-addr:value = '192.0.2.44']"],
    ['2001:db8::1', 'ip', "[ipv6-addr:value = '2001:db8::1']"],
    ['evil.example', 'domain', "[domain-name:value = 'evil.example']"],
    ["https://evil.example/a'b", 'url', "[url:value = 'https://evil.example/a\\'b']"],
    ['a'.repeat(32), 'hash', `[file:hashes.'MD5' = '${'a'.repeat(32)}']`],
    ['b'.repeat(40), 'hash', `[file:hashes.'SHA-1' = '${'b'.repeat(40)}']`],
    ['c'.repeat(64), 'hash', `[file:hashes.'SHA-256' = '${'c'.repeat(64)}']`],
    ['AS3333', 'asn', '[autonomous-system:number = 3333]'],
  ];
  for (const [indicator, type, pattern] of cases) {
    const bundle = toStixBundle(enrichment(indicator, type), { now: () => '2026-08-21T01:00:00.000Z', uuid });
    assert.equal(bundle.type, 'bundle');
    assert.equal(bundle.objects[0].type, 'indicator');
    assert.equal(bundle.objects[0].spec_version, '2.1');
    assert.equal(bundle.objects[0].pattern_type, 'stix');
    assert.equal(bundle.objects[0].pattern, pattern);
    assert.equal('confidence' in bundle.objects[0], false);
  }
});

test('CVE exports as a Vulnerability SDO rather than fabricated indicator pattern', () => {
  const bundle = toStixBundle(enrichment('CVE-2026-12345', 'cve'), { now: () => '2026-08-21T01:00:00.000Z', uuid });
  assert.equal(bundle.objects.length, 1);
  assert.equal(bundle.objects[0].type, 'vulnerability');
  assert.equal(bundle.objects[0].name, 'CVE-2026-12345');
  assert.deepEqual(bundle.objects[0].external_references, [{ source_name: 'cve', external_id: 'CVE-2026-12345' }]);
});

test('ATT&CK source STIX IDs are preserved and only bounded fields are mapped', () => {
  const attack = ev('attack-taxii', 'attack_knowledge', {
    attackId: 'T1059.001', stixId: 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736', stixType: 'attack-pattern', name: 'PowerShell', description: 'PowerShell technique.', domain: 'enterprise-attack', tactics: ['execution'], platforms: ['Windows'], version: '1.5', revoked: false, deprecated: false,
  }, ['https://attack.mitre.org/techniques/T1059/001/']);
  attack.observation.firstSeen = '2020-03-09T14:00:00.000Z';
  attack.observation.lastSeen = '2026-05-12T14:00:00.000Z';
  const bundle = toStixBundle(enrichment('T1059.001', 'attack', [attack]), { now: () => '2026-08-21T01:00:00.000Z', uuid });
  const object = bundle.objects[0];
  assert.equal(object.id, 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736');
  assert.equal(object.type, 'attack-pattern');
  assert.equal(object.name, 'PowerShell');
  assert.equal(object.created, '2020-03-09T14:00:00.000Z');
  assert.equal(object.modified, '2026-05-12T14:00:00.000Z');
  assert.deepEqual(object.kill_chain_phases, [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }]);
  assert.equal(object.external_references[0].external_id, 'T1059.001');
});

test('external references accept only bounded http(s) URLs and are deduplicated', () => {
  const evidence = [ev('p', 'reputation', {}, ['https://example.test/a', 'https://example.test/a', 'javascript:alert(1)', 'file:///etc/passwd'])];
  const bundle = toStixBundle(enrichment('evil.example', 'domain', evidence), { now: () => '2026-08-21T01:00:00.000Z', uuid });
  assert.deepEqual(bundle.objects[0].external_references, [{ source_name: 'p', url: 'https://example.test/a' }]);
});

test('actor and malware SDOs are emitted only from explicit supported relationships', () => {
  const relationships = [
    { type: 'attributed_to', source: 'campaign:x', target: 'APT Demo', targetType: 'actor', provider: 'p' },
    { type: 'uses', source: 'campaign:x', target: 'DemoMalware', targetType: 'malware', provider: 'p' },
  ];
  const bundle = toStixBundle(enrichment('evil.example', 'domain', [], relationships), { now: () => '2026-08-21T01:00:00.000Z', uuid });
  assert.ok(bundle.objects.some(object => object.type === 'threat-actor' && object.name === 'APT Demo'));
  assert.ok(bundle.objects.some(object => object.type === 'malware' && object.name === 'DemoMalware'));
});

test('STIX export enforces object cap and rejects non-gateway-shaped input', () => {
  const relationships = Array.from({ length: 110 }, (_, i) => ({ type: 'attributed_to', source: 'x', target: `actor-${i}`, targetType: 'actor', provider: 'p' }));
  const bundle = toStixBundle(enrichment('evil.example', 'domain', [], relationships), { maxObjects: 10, now: () => '2026-08-21T01:00:00.000Z', uuid });
  assert.equal(bundle.objects.length, 10);
  assert.throws(() => toStixBundle({ type: 'domain', indicator: 'evil.example' }), /gateway enrichment/);
  assert.throws(() => toStixBundle(enrichment('evil.example', 'domain'), { maxObjects: 101 }), /maxObjects/);
});

test('STIX export ignores kernel-derived conclusions and serializes only defensible raw evidence and explicit relationships', () => {
  const input = enrichment('203.0.113.7', 'ip', [ev('p', 'reputation')], []);
  input.intelligence = {
    schemaVersion: '1.0', type: 'ip', policy: { type: 'ip', version: '1.0' },
    analystPriority: { level: 'immediate', reasons: ['ip_priority_immediate'], evidenceFingerprints: [] },
    evidenceStrength: { level: 'strong', reasons: ['ip_strength_strong_independent_direct'], providers: ['p'], evidenceFingerprints: [] },
    pivotCandidates: [{ type: 'domain', value: 'kernel-only.example', reasonCodes: ['derived_only'] }],
    relationshipValue: [{ targetType: 'domain', target: 'kernel-only.example', valueClass: 'direct' }],
  };
  const bundle = toStixBundle(input, { now: () => '2026-08-21T01:00:00.000Z', uuid });
  const json = JSON.stringify(bundle);
  assert.equal(json.includes('ip_priority_immediate'), false);
  assert.equal(json.includes('ip_strength_strong_independent_direct'), false);
  assert.equal(json.includes('kernel-only.example'), false);
  assert.equal(json.includes('analystPriority'), false);
  assert.equal(json.includes('evidenceStrength'), false);
});

function adapter() {
  return Object.freeze({
    name: 'rdap', types: ['domain'], observationTypes: ['registration'], costClass: 'free', tier: 1, timeoutMs: 5000,
    cacheTtlMs: 1000, negativeCacheTtlMs: 1000, maxResponseBytes: 1024, fixedHosts: ['fixture.invalid'], methods: ['GET'], protocols: ['https:'], parserVersion: 'test', sourceUrl: 'https://fixture.invalid/',
    async run() { return { observationType: 'registration', verdict: 'unknown', attributes: {}, relationships: [], references: ['https://example.test/context'] }; },
  });
}
function req(body, token = 'secret') { return { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body }; }

test('authenticated STIX API performs normal enrichment first and rejects direct enrichment injection', async () => {
  const app = createApp({ env: { PARA11AX_TOKEN: 'secret' }, adapters: [adapter()] });
  assert.equal((await app.handleStix(req({ indicator: 'evil.example' }, 'bad'))).status, 401);
  const injected = await app.handleStix(req({ indicator: 'evil.example', enrichment: { status: 'ok' } }));
  assert.equal(injected.status, 400);
  const out = await app.handleStix(req({ indicator: 'evil.example', profile: 'full' }));
  assert.equal(out.status, 200);
  assert.equal(out.body.type, 'bundle');
  assert.equal(out.body.objects[0].type, 'indicator');
});

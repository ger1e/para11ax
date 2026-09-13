import test from 'node:test';
import assert from 'node:assert/strict';

import { createDomainInvestigation, importDomainVulnerabilities } from '../src/core/domain-investigation.js';
import { toDomainInvestigationStix } from '../src/export/domain-investigation-stix.js';

function enrichment() {
  return {
    schemaVersion: '2.0', gatewayVersion: 'test', requestId: 'stix-test',
    indicator: 'suspicious.example', type: 'domain', queriedAt: '2026-09-13T12:00:00.000Z', profile: 'standard', status: 'ok',
    evidence: [{
      provider: 'virustotal', indicator: 'suspicious.example', type: 'domain',
      observation: { kind: 'reputation', verdict: 'malicious', confidence: null, firstSeen: null, lastSeen: null, tags: [], malwareFamily: null, actor: null, attributes: {} },
      relationships: [
        { targetType: 'ip', target: '203.0.113.40', relationship: 'resolves_to' },
        { targetType: 'url', target: 'https://suspicious.example/login', relationship: 'observed_url' },
      ],
      references: ['https://www.virustotal.com/gui/domain/suspicious.example'], retrievedAt: '2026-09-13T12:00:00.000Z', cacheState: 'miss', durationMs: 1,
      integrity: { rawHash: null, parserVersion: '1', fingerprint: '1'.repeat(64) },
      semantics: { class: 'provider_claim', semanticClass: 'reputation', sourceRole: 'community' },
    }],
    relationships: [], coverage: {}, limitations: [], failures: [],
    huntContext: { indicator: 'suspicious.example', type: 'domain', firstSeen: null, lastSeen: null, families: [], actors: [], sourceReferences: [] },
  };
}

test('exports deterministic STIX 2.1 indicators and vulnerabilities from Domain Investigation IOCs', () => {
  let artifact = createDomainInvestigation(enrichment());
  artifact = importDomainVulnerabilities(artifact, [{ cve: 'CVE-2026-12345', severity: 'high', source: 'nuclei' }]);
  const a = toDomainInvestigationStix(artifact);
  const b = toDomainInvestigationStix(artifact);

  assert.deepEqual(a, b);
  assert.equal(a.type, 'bundle');
  assert.match(a.id, /^bundle--[0-9a-f-]{36}$/);
  assert.ok(a.objects.every(object => object.spec_version === '2.1'));
  assert.ok(a.objects.some(object => object.type === 'indicator' && object.pattern.includes("domain-name:value = 'suspicious.example'")));
  assert.ok(a.objects.some(object => object.type === 'indicator' && object.pattern.includes("ipv4-addr:value = '203.0.113.40'")));
  assert.ok(a.objects.some(object => object.type === 'indicator' && object.pattern.includes("url:value = 'https://suspicious.example/login'")));
  assert.ok(a.objects.some(object => object.type === 'vulnerability' && object.name === 'CVE-2026-12345'));
});

test('does not fabricate provider references for imported-only IOCs', () => {
  let artifact = createDomainInvestigation({ ...enrichment(), evidence: [] });
  artifact = importDomainVulnerabilities(artifact, [{ cve: 'CVE-2026-22222', source: 'nuclei', reference: 'https://scanner.invalid/run/9' }]);
  const bundle = toDomainInvestigationStix(artifact);
  const cve = bundle.objects.find(object => object.type === 'vulnerability' && object.name === 'CVE-2026-22222');
  assert.ok(cve);
  assert.deepEqual(cve.external_references, [{ source_name: 'cve', external_id: 'CVE-2026-22222' }]);
});

test('enforces the 100-object cap and validates requested bounds', () => {
  const e = enrichment();
  e.evidence[0].relationships = Array.from({ length: 120 }, (_, index) => ({ targetType: 'ip', target: `198.51.100.${(index % 250) + 1}`, relationship: 'related' }));
  const artifact = createDomainInvestigation(e);
  assert.equal(toDomainInvestigationStix(artifact).objects.length, 100);
  assert.equal(toDomainInvestigationStix(artifact, { maxObjects: 10 }).objects.length, 10);
  assert.throws(() => toDomainInvestigationStix(artifact, { maxObjects: 101 }), /100/);
});

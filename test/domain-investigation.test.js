import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createDomainInvestigation,
  importDomainSurface,
  importDomainVulnerabilities,
} from '../src/core/domain-investigation.js';

const fp = char => char.repeat(64);

function evidence({
  provider,
  verdict = 'unknown',
  kind = 'reputation',
  semanticClass = 'reputation',
  sourceRole = 'community',
  relationships = [],
  fingerprint = fp('a'),
  references = [],
} = {}) {
  return {
    provider,
    indicator: 'suspicious.example',
    type: 'domain',
    observation: {
      kind,
      verdict,
      confidence: null,
      firstSeen: null,
      lastSeen: null,
      tags: [],
      malwareFamily: null,
      actor: null,
      attributes: {},
    },
    relationships,
    references,
    retrievedAt: '2026-09-13T12:00:00.000Z',
    cacheState: 'miss',
    durationMs: 1,
    integrity: { rawHash: null, parserVersion: '1', fingerprint },
    semantics: {
      class: semanticClass === 'network_context' ? 'provider_claim' : 'provider_claim',
      semanticClass,
      sourceRole,
    },
  };
}

function enrichment(items = []) {
  return {
    schemaVersion: '2.0',
    gatewayVersion: 'test',
    requestId: 'req-domain-investigation',
    indicator: 'suspicious.example',
    type: 'domain',
    queriedAt: '2026-09-13T12:00:00.000Z',
    profile: 'standard',
    status: 'ok',
    evidence: items,
    relationships: items.flatMap(item => item.relationships ?? []),
    coverage: {},
    limitations: [],
    failures: [],
    huntContext: {
      indicator: 'suspicious.example',
      type: 'domain',
      firstSeen: null,
      lastSeen: null,
      families: [],
      actors: [],
      sourceReferences: [],
    },
  };
}

function byValue(artifact, value) {
  return artifact.iocs.find(item => item.value === value);
}

function recommendation(artifact, value) {
  return artifact.recommendations.find(item => item.value === value);
}

test('builds a frozen Domain Investigation v1 artifact from matching domain Evidence v2', () => {
  const artifact = createDomainInvestigation(enrichment([
    evidence({
      provider: 'webamon',
      verdict: 'observed',
      kind: 'web_intelligence',
      semanticClass: 'web_intelligence',
      fingerprint: fp('1'),
      relationships: [
        { targetType: 'ip', target: '203.0.113.8', relationship: 'observed_ip' },
        { targetType: 'domain', target: 'cdn.suspicious.example', relationship: 'observed_domain' },
      ],
      references: ['https://webamon.com/api'],
    }),
  ]));

  assert.equal(artifact.schemaVersion, 'domain-investigation-v1.0');
  assert.deepEqual(artifact.target, { type: 'domain', value: 'suspicious.example' });
  assert.equal(artifact.passive.webamon.present, true);
  assert.deepEqual(artifact.passive.providers, ['webamon']);
  assert.ok(artifact.passive.evidenceFingerprints.includes(fp('1')));
  assert.ok(byValue(artifact, '203.0.113.8'));
  assert.ok(byValue(artifact, 'cdn.suspicious.example'));
  assert.equal(Object.isFrozen(artifact), true);
  assert.equal(Object.isFrozen(artifact.iocs), true);
  assert.equal(Object.isFrozen(artifact.handoff), true);
});

test('fails closed when passive enrichment is not Evidence v2 for the same domain', () => {
  assert.throws(() => createDomainInvestigation({ ...enrichment(), type: 'ip' }), /domain/i);
  assert.throws(() => createDomainInvestigation({ ...enrichment(), indicator: 'other.example' }, 'suspicious.example'), /target|indicator|domain/i);
  assert.throws(() => createDomainInvestigation({ ...enrichment(), schemaVersion: 'legacy-v1' }), /evidence/i);
});

test('normalizes and deduplicates passive relationship IOCs with evidence provenance', () => {
  const artifact = createDomainInvestigation(enrichment([
    evidence({
      provider: 'virustotal',
      verdict: 'malicious',
      fingerprint: fp('2'),
      relationships: [
        { targetType: 'ip', target: '203.0.113.8', relationship: 'resolves_to' },
        { targetType: 'ip', target: '203.0.113.8', relationship: 'observed_ip' },
        { targetType: 'url', target: 'https://suspicious.example/login', relationship: 'observed_url' },
      ],
    }),
    evidence({
      provider: 'otx',
      verdict: 'malicious',
      fingerprint: fp('3'),
      relationships: [{ targetType: 'ip', target: '203.0.113.8', relationship: 'related' }],
    }),
  ]));

  const ip = byValue(artifact, '203.0.113.8');
  assert.equal(ip.type, 'ip');
  assert.deepEqual(ip.authorities, ['evidence_v2']);
  assert.deepEqual(ip.providers, ['otx', 'virustotal']);
  assert.deepEqual(ip.evidenceFingerprints, [fp('2'), fp('3')]);
  assert.equal(artifact.iocs.filter(item => item.value === '203.0.113.8').length, 1);
});

test('imports surface and vulnerability findings only as bounded operator context and rebuilds immutably', () => {
  const base = createDomainInvestigation(enrichment([]));
  const surfaced = importDomainSurface(base, [
    {
      host: 'admin.suspicious.example',
      ip: '203.0.113.10',
      url: 'https://admin.suspicious.example/',
      port: 443,
      protocol: 'https',
      service: 'nginx',
      technology: 'nginx',
      status: 200,
      source: 'authorized-discovery',
      reference: 'https://scanner.invalid/run/1',
    },
  ]);
  const vulnerable = importDomainVulnerabilities(surfaced, [
    {
      host: 'admin.suspicious.example',
      url: 'https://admin.suspicious.example/',
      templateId: 'CVE-2026-12345-check',
      cve: 'CVE-2026-12345',
      severity: 'high',
      title: 'Authorized test finding',
      matchedAt: 'https://admin.suspicious.example/',
      source: 'nuclei',
      reference: 'https://scanner.invalid/run/2',
    },
  ]);

  assert.equal(base.imports.surface.length, 0);
  assert.equal(base.imports.vulnerabilities.length, 0);
  assert.equal(surfaced.imports.surface.length, 1);
  assert.equal(surfaced.imports.vulnerabilities.length, 0);
  assert.equal(vulnerable.imports.vulnerabilities.length, 1);
  assert.deepEqual(byValue(vulnerable, '203.0.113.10').authorities, ['operator_context']);
  assert.deepEqual(byValue(vulnerable, 'CVE-2026-12345').authorities, ['operator_context']);
  assert.ok(vulnerable.imports.surface[0].id.startsWith('SURF-'));
  assert.ok(vulnerable.imports.vulnerabilities[0].id.startsWith('VULN-'));
  assert.equal(Object.isFrozen(vulnerable.imports.surface[0]), true);
});

test('rejects oversized, nested, credential-bearing or malformed operator imports', () => {
  const artifact = createDomainInvestigation(enrichment([]));
  assert.throws(() => importDomainSurface(artifact, Array.from({ length: 501 }, () => ({ host: 'x.example' }))), /500|limit/i);
  assert.throws(() => importDomainSurface(artifact, [{ host: { nested: 'nope' } }]), /scalar|field|host/i);
  assert.throws(() => importDomainSurface(artifact, [{ host: 'x'.repeat(4097) }]), /4096|length/i);
  assert.throws(() => importDomainSurface(artifact, [{ reference: 'file:///etc/passwd' }]), /reference|http/i);
  assert.throws(() => importDomainSurface(artifact, [{ reference: 'https://user:pass@example.com/x' }]), /credential|reference/i);
  assert.throws(() => importDomainVulnerabilities(artifact, [{ cve: ['CVE-2026-1', { nested: true }] }]), /scalar|array|cve/i);
});

test('two independent exact malicious Evidence v2 sources can recommend BLOCK', () => {
  const artifact = createDomainInvestigation(enrichment([
    evidence({ provider: 'virustotal', verdict: 'malicious', semanticClass: 'reputation', fingerprint: fp('4') }),
    evidence({ provider: 'urlhaus', verdict: 'malicious', kind: 'malware_distribution', semanticClass: 'reputation', fingerprint: fp('5') }),
  ]));

  const rec = recommendation(artifact, 'suspicious.example');
  assert.equal(rec.disposition, 'BLOCK');
  assert.equal(rec.ruleId, 'DI-BLOCK-2-DIRECT');
  assert.deepEqual(rec.directSources, ['urlhaus', 'virustotal']);
  assert.deepEqual(rec.authority, ['evidence_v2']);
});

test('one direct malicious source plus independent contextual threat intelligence is only BLOCK_CANDIDATE', () => {
  const artifact = createDomainInvestigation(enrichment([
    evidence({ provider: 'virustotal', verdict: 'malicious', semanticClass: 'reputation', fingerprint: fp('6') }),
    evidence({ provider: 'otx', verdict: 'suspicious', kind: 'community_intelligence', semanticClass: 'threat_context', fingerprint: fp('7') }),
  ]));

  const rec = recommendation(artifact, 'suspicious.example');
  assert.equal(rec.disposition, 'BLOCK_CANDIDATE');
  assert.equal(rec.ruleId, 'DI-CANDIDATE-DIRECT-CONTEXT');
  assert.deepEqual(rec.directSources, ['virustotal']);
  assert.deepEqual(rec.contextSources, ['otx']);
});

test('network, exposure, Webamon and operator context never become a malicious vote by themselves', () => {
  let artifact = createDomainInvestigation(enrichment([
    evidence({ provider: 'rdap', verdict: 'observed', kind: 'registration', semanticClass: 'network_context', sourceRole: 'authoritative', fingerprint: fp('8') }),
    evidence({ provider: 'shodan', verdict: 'observed', kind: 'internet_exposure', semanticClass: 'network_context', fingerprint: fp('9') }),
    evidence({ provider: 'webamon', verdict: 'observed', kind: 'web_intelligence', semanticClass: 'web_intelligence', fingerprint: fp('a') }),
  ]));
  artifact = importDomainSurface(artifact, [{ host: 'suspicious.example', port: 443, source: 'authorized-discovery' }]);

  const rec = recommendation(artifact, 'suspicious.example');
  assert.notEqual(rec.disposition, 'BLOCK');
  assert.notEqual(rec.disposition, 'BLOCK_CANDIDATE');
  assert.ok(['MONITOR', 'DO_NOT_BLOCK'].includes(rec.disposition));
  assert.equal(rec.directSources.length, 0);
});

test('explicit negative evidence is retained as contradiction pressure and prevents BLOCK', () => {
  const artifact = createDomainInvestigation(enrichment([
    evidence({ provider: 'virustotal', verdict: 'malicious', semanticClass: 'reputation', fingerprint: fp('b') }),
    evidence({ provider: 'urlhaus', verdict: 'malicious', semanticClass: 'reputation', fingerprint: fp('c') }),
    evidence({ provider: 'openphish', verdict: 'clean', kind: 'phishing_feed', semanticClass: 'reputation', fingerprint: fp('d') }),
  ]));

  const rec = recommendation(artifact, 'suspicious.example');
  assert.notEqual(rec.disposition, 'BLOCK');
  assert.ok(rec.contradictions.some(item => item.provider === 'openphish'));
});

test('report and handoff preserve authority boundaries and compact continuity state', () => {
  let artifact = createDomainInvestigation(enrichment([
    evidence({ provider: 'webamon', verdict: 'observed', kind: 'web_intelligence', semanticClass: 'web_intelligence', fingerprint: fp('e') }),
  ]));
  artifact = importDomainSurface(artifact, [{ host: 'admin.suspicious.example', ip: '203.0.113.11', source: 'authorized-discovery' }]);

  assert.match(artifact.report.text, /operator context/i);
  assert.match(artifact.report.text, /did not execute active scanning/i);
  assert.equal(artifact.handoff.schemaVersion, 'domain-investigation-handoff-v1.0');
  assert.equal(artifact.handoff.target.value, 'suspicious.example');
  assert.ok(artifact.handoff.evidence.providers.includes('webamon'));
  assert.ok(artifact.handoff.evidence.fingerprints.includes(fp('e')));
  assert.ok(artifact.handoff.operatorContext.recordIds.includes(artifact.imports.surface[0].id));
  assert.ok(Array.isArray(artifact.handoff.nextActions));
  assert.ok(artifact.handoff.contextBudget.serializedBytes < 128_000);
  assert.equal(JSON.stringify(artifact.handoff).includes('authorized-discovery'), false);
});

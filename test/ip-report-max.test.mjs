import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as viewModel from '../app/view-model.js';
import { interpretCommand } from '../app/shell.js';

const sample = {
  indicator: '8.8.8.8',
  type: 'ip',
  requestId: 'req-ip-report',
  profile: 'full',
  status: 'partial',
  durationMs: 4120,
  providerSummary: { ok: 8, failed: 1, skipped: 0, cached: 2 },
  failures: [
    { provider: 'webamon', reason: 'timeout', attempts: 2, retrievedAt: '2026-08-30T00:10:00.000Z' },
  ],
  evidence: [
    {
      provider: 'ipinfo',
      observation: {
        kind: 'network_identity', verdict: 'unknown', confidence: null,
        attributes: { ip: '8.8.8.8', asn: 'AS15169', organization: 'Google LLC', domain: 'google.com', country: 'US', continent: 'NA' },
      },
      references: ['https://ipinfo.io/'], integrity: { parserVersion: '1', fingerprint: 'a'.repeat(64) },
    },
    {
      provider: 'ripestat',
      observation: {
        kind: 'routing', verdict: 'unknown', confidence: null,
        attributes: { ip: '8.8.8.8', asn: 'AS15169', prefix: '8.8.8.0/24' },
      },
      references: ['https://stat.ripe.net/'], integrity: { parserVersion: '1', fingerprint: 'b'.repeat(64) },
    },
    {
      provider: 'rdap',
      observation: {
        kind: 'registration', verdict: 'unknown', confidence: null,
        attributes: { ip: '8.8.8.8', name: 'GOGL', country: 'US', startAddress: '8.8.8.0', endAddress: '8.8.8.255' },
      },
      references: ['https://rdap.arin.net/'], integrity: { parserVersion: '1', fingerprint: 'c'.repeat(64) },
    },
    {
      provider: 'shodan',
      observation: {
        kind: 'internet_exposure', verdict: 'observed', confidence: null,
        attributes: { ports: [53, 443], services: ['dns', 'https'], hostnames: ['dns.google'] },
      },
      references: ['https://shodan.io/'], integrity: { parserVersion: '1', fingerprint: 'd'.repeat(64) },
    },
    {
      provider: 'abuseipdb',
      observation: {
        kind: 'abuse_reports', verdict: 'observed', confidence: 0.9,
        attributes: { abuseConfidenceScore: 65, totalReports: 42, distinctUsers: 19, lastReportedAt: '2026-08-29T18:00:00.000Z' },
      },
      references: ['https://abuseipdb.com/'], integrity: { parserVersion: '1', fingerprint: 'e'.repeat(64) },
    },
    {
      provider: 'greynoise',
      observation: {
        kind: 'internet_noise', verdict: 'malicious', confidence: null,
        attributes: { noise: true, riot: false, classification: 'malicious', name: 'scanner' },
      },
      references: ['https://greynoise.io/'], integrity: { parserVersion: '1', fingerprint: 'f'.repeat(64) },
    },
    {
      provider: 'spamhaus-drop',
      observation: {
        kind: 'drop_netblock', verdict: 'not_listed', confidence: null,
        attributes: { listed: false, cidr: null },
      },
      references: ['https://spamhaus.org/'], integrity: { parserVersion: '1', fingerprint: '1'.repeat(64) },
    },
    {
      provider: 'webamon',
      observation: {
        kind: 'web_intelligence', verdict: 'no_result', confidence: null,
        attributes: { resultCount: 0, returnedCount: 0, maxRiskScore: null },
      },
      references: ['https://webamon.com/'], integrity: { parserVersion: '1', fingerprint: '2'.repeat(64) },
    },
  ],
  relationships: [
    { type: 'domain', value: 'dns.google', relationship: 'observed_domain', provider: 'shodan' },
    { type: 'asn', value: 'AS15169', relationship: 'origin_asn', provider: 'ripestat' },
  ],
  correlation: {
    freshness: 'current',
    huntability: { level: 'high', rationale: 'Observed abuse/scanner signals and infrastructure pivots are available.' },
    corroboration: [{ providers: ['abuseipdb', 'greynoise'], kind: 'reputation', verdict: 'observed' }],
    contradictions: [],
    riskAxes: {},
  },
};

function build() {
  assert.equal(typeof viewModel.buildIpAnalystReport, 'function', 'view-model must expose buildIpAnalystReport');
  return viewModel.buildIpAnalystReport({
    overview: viewModel.buildOverview(sample),
    evidence: viewModel.buildEvidence(sample),
    correlation: viewModel.buildCorrelation(sample),
    relationships: viewModel.buildRelationships(sample),
    coverage: viewModel.buildCoverage(sample),
  });
}

test('IP enrichment compiles into one ordered deterministic analyst report', () => {
  const report = build();
  assert.equal(report.title, 'IP INTELLIGENCE REPORT // 8.8.8.8');
  assert.deepEqual(report.sections.map(section => section.id), [
    'identity', 'registration-routing', 'geo-network', 'exposure', 'reputation-abuse',
    'malware-c2-ransomware', 'tor-scanner', 'related-infrastructure',
    'correlation', 'temporal-context', 'attack-behavior', 'analyst-actions', 'huntability', 'coverage', 'source-references',
  ]);
  const sources = report.sections.find(section => section.id === 'source-references');
  assert.equal(sources.facts.length, 8);
  assert.ok(sources.facts.some(fact => fact.value === 'https://ipinfo.io/'));
  assert.equal(report.assessment.state, 'ACTIONABLE THREAT EVIDENCE');
  assert.match(report.assessment.summary, /AS15169/i);
  assert.match(report.assessment.summary, /Google LLC/i);
  assert.match(report.assessment.summary, /2 independent provider/i);
});

test('legacy IP envelope without intelligence preserves the existing report fallback', () => {
  const report = build();
  assert.equal(viewModel.buildOverview(sample).intelligence ?? null, null);
  assert.equal(report.assessment.decisionSource, 'REPORT FALLBACK');
  assert.equal(report.assessment.state, 'ACTIONABLE THREAT EVIDENCE');
  assert.doesNotMatch(viewModel.renderIpAnalystReportText(report), /INTELLIGENCE KERNEL/i);
});

test('IP report deduplicates repeated facts and keeps corroborating provenance', () => {
  const report = build();
  const identity = report.sections.find(section => section.id === 'identity');
  const asn = identity.facts.find(fact => fact.label === 'ASN' && fact.value === 'AS15169');
  assert.ok(asn);
  assert.deepEqual(asn.sources, ['ipinfo', 'ripestat']);
  const country = report.sections.find(section => section.id === 'geo-network').facts.find(fact => fact.label === 'COUNTRY' && fact.value === 'US');
  assert.ok(country);
  assert.deepEqual(country.sources, ['ipinfo', 'rdap']);
});

test('IP report collapses no-result noise while preserving explicit negative findings', () => {
  const report = build();
  const visibleProviders = report.sections.flatMap(section => section.items ?? []).map(item => item.provider).filter(Boolean);
  assert.ok(!visibleProviders.includes('webamon'), 'no-result Webamon evidence should not become a main report card');
  const reputation = report.sections.find(section => section.id === 'reputation-abuse');
  assert.ok(reputation.items.some(item => item.provider === 'spamhaus-drop' && /not listed/i.test(item.verdict)));
});

test('coverage remains compact and failures do not dominate the report', () => {
  const report = build();
  const coverage = report.sections.find(section => section.id === 'coverage');
  assert.match(coverage.summary, /8 succeeded/i);
  assert.equal(coverage.failures.length, 1);
  assert.equal(coverage.failures[0].provider, 'webamon');
  assert.match(coverage.failures[0].label, /timeout/i);
  assert.ok(report.sections.findIndex(section => section.id === 'coverage') > report.sections.findIndex(section => section.id === 'reputation-abuse'));
});

test('default brief renderer switches IP results to the coherent IP report', () => {
  const renderers = readFileSync('app/renderers.js', 'utf8');
  assert.match(renderers, /overview\.type\s*===\s*['"]ip['"]/);
  assert.match(renderers, /buildIpAnalystReport/);
  assert.match(renderers, /IP INTELLIGENCE REPORT/);
});

test('IP analyst report has explicit dense desktop and mobile readability rules', () => {
  const css = readFileSync('app/analyst-facts.css', 'utf8');
  assert.match(css, /\.ip-intelligence-report\s*\{/);
  assert.match(css, /\.ip-report-assessment\s*\{/);
  assert.match(css, /\.ip-source-list\s*\{/);
  assert.match(css, /\.ip-source-line\s*\{/);
  assert.match(css, /@media\(max-width:430px\)[\s\S]*\.ip-report-title/);
  assert.match(css, /@media\(max-width:430px\)[\s\S]*\.ip-source-line/);
});

test('copy report command produces analyst-readable text instead of JSON', () => {
  assert.equal(typeof viewModel.renderIpAnalystReportText, 'function', 'view-model must expose renderIpAnalystReportText');
  const text = viewModel.renderIpAnalystReportText(build());
  assert.match(text, /^IP INTELLIGENCE REPORT \/\/ 8\.8\.8\.8/m);
  assert.match(text, /EXECUTIVE ASSESSMENT/);
  assert.match(text, /IDENTITY & ASN/);
  assert.match(text, /ASN:\s+AS15169\s+\[ipinfo \+ ripestat\]/i);
  assert.match(text, /WEBAMON:\s+UPSTREAM TIMEOUT/i);
  assert.doesNotMatch(text, /^\s*[{}]\s*$/m);
  assert.deepEqual(interpretCommand('copy report', { authenticated: true, profile: 'full' }), { action: 'copy', target: 'report', historySafe: true });
  const shellExecutor = readFileSync('app/shell-browser-executor.js', 'utf8');
  assert.match(shellExecutor, /target === ['"]report['"]/);
  assert.match(shellExecutor, /renderIpAnalystReportText/);
  assert.match(shellExecutor, /buildOverview\(current\)/);
  assert.match(shellExecutor, /buildEvidence\(current\)/);
});

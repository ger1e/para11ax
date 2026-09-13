import test from 'node:test';
import assert from 'node:assert/strict';

import { scoreCtiCase } from '../src/eval/domains/cti.js';
import { scoreProvenanceCase } from '../src/eval/domains/provenance.js';
import { scoreClassificationCase } from '../src/eval/domains/classification.js';
import { scoreAttackCase } from '../src/eval/domains/attack.js';
import { scoreKqlCase } from '../src/eval/domains/kql.js';

function normalized(result) {
  assert.equal(typeof result.score, 'number');
  assert.ok(result.score >= 0 && result.score <= 1);
  assert.equal(typeof result.hardFail, 'boolean');
  assert.ok(Array.isArray(result.violations));
  assert.deepEqual(result.violations, [...result.violations].sort());
  assert.equal(typeof result.metrics, 'object');
  assert.deepEqual(result.humanReview, { required: false, fields: [] });
  assert.equal(result.scorerVersion, '1.0.0');
  return result;
}

const ctiCase = {
  expected: {
    entities: ['actor:ORCHID', 'malware:TEST-RAT', 'cve:CVE-2026-12345'],
    relationships: ['uses:ORCHID:TEST-RAT', 'exploits:TEST-RAT:CVE-2026-12345'],
  },
};

test('CTI scorer rewards exact structured extraction and penalizes omissions/inventions', () => {
  const perfect = normalized(scoreCtiCase(ctiCase, {
    entities: [...ctiCase.expected.entities],
    relationships: [...ctiCase.expected.relationships],
  }));
  assert.equal(perfect.score, 1);
  assert.equal(perfect.hardFail, false);

  const partial = normalized(scoreCtiCase(ctiCase, {
    entities: ['actor:ORCHID', 'malware:TEST-RAT', 'actor:INVENTED'],
    relationships: ['uses:ORCHID:TEST-RAT'],
  }));
  assert.ok(partial.score > 0 && partial.score < 1);
  assert.ok(partial.violations.includes('CTI_UNEXPECTED_ENTITY'));
  assert.ok(partial.violations.includes('CTI_MISSING_RELATIONSHIP'));
});

const provenanceCase = {
  expected: {
    claims: [
      { claimId: 'claim-actor-malware', allowedEvidenceIds: ['ev-1'], required: true, critical: true },
      { claimId: 'claim-c2', allowedEvidenceIds: ['ev-2'], required: true, critical: false },
    ],
    criticalUnsupportedClaimIds: ['claim-exclusive-attribution'],
  },
};

test('provenance scorer rewards supported claims and penalizes invalid citations', () => {
  const perfect = normalized(scoreProvenanceCase(provenanceCase, {
    claims: [
      { claimId: 'claim-actor-malware', evidenceIds: ['ev-1'] },
      { claimId: 'claim-c2', evidenceIds: ['ev-2'] },
    ],
  }));
  assert.equal(perfect.score, 1);
  assert.equal(perfect.hardFail, false);

  const invalid = normalized(scoreProvenanceCase(provenanceCase, {
    claims: [
      { claimId: 'claim-actor-malware', evidenceIds: ['ev-404'] },
      { claimId: 'claim-c2', evidenceIds: [] },
    ],
  }));
  assert.ok(invalid.score < 1);
  assert.ok(invalid.violations.some(item => item.startsWith('PROVENANCE_INVALID_EVIDENCE_REF:')));
  assert.equal(invalid.hardFail, true);
});

test('critical unsupported provenance claim is a hard failure', () => {
  const result = normalized(scoreProvenanceCase(provenanceCase, {
    claims: [
      { claimId: 'claim-actor-malware', evidenceIds: ['ev-1'] },
      { claimId: 'claim-c2', evidenceIds: ['ev-2'] },
      { claimId: 'claim-exclusive-attribution', evidenceIds: ['ev-1'] },
    ],
  }));
  assert.equal(result.hardFail, true);
  assert.ok(result.violations.includes('PROVENANCE_CRITICAL_UNSUPPORTED:claim-exclusive-attribution'));
});

test('classification scorer uses exact item labels and penalizes wrong/extra labels', () => {
  const evalCase = {
    expected: {
      items: [
        { id: 'item-1', label: 'ioc' },
        { id: 'item-2', label: 'ioa' },
        { id: 'item-3', label: 'ttp' },
      ],
    },
  };
  assert.equal(normalized(scoreClassificationCase(evalCase, { items: evalCase.expected.items })).score, 1);
  const partial = normalized(scoreClassificationCase(evalCase, {
    items: [
      { id: 'item-1', label: 'ioa' },
      { id: 'item-2', label: 'ioa' },
      { id: 'item-4', label: 'ioc' },
    ],
  }));
  assert.ok(partial.score < 1);
  assert.ok(partial.violations.includes('CLASSIFICATION_WRONG_LABEL:item-1'));
  assert.ok(partial.violations.includes('CLASSIFICATION_UNEXPECTED_ITEM:item-4'));
});

test('ATT&CK scorer penalizes over-mapping instead of rewarding larger lists', () => {
  const evalCase = { expected: { techniques: ['T1059.001', 'T1071.001'] } };
  assert.equal(normalized(scoreAttackCase(evalCase, { techniques: ['T1071.001', 'T1059.001'] })).score, 1);
  const over = normalized(scoreAttackCase(evalCase, {
    techniques: ['T1059.001', 'T1071.001', 'T1021.001'],
  }));
  assert.ok(over.score < 1);
  assert.equal(over.metrics.precision < 1, true);
  assert.ok(over.violations.includes('ATTACK_UNEXPECTED_TECHNIQUE:T1021.001'));
});

const kqlCase = {
  expected: {
    requiredTables: ['DeviceProcessEvents'],
    forbiddenTokens: ['Sysmon', '_GetWatchlist', 'ASIM'],
    requiredRegexes: ['ago\\s*\\(', 'summarize'],
    forbiddenRegexes: ['union\\s+\\*'],
    requiredHeaderKeys: [
      'Title', 'Description', 'Suspicious Behavior', 'MITRE ATT&CK',
      'Pyramid of Pain', 'Kill Chain', 'CTI URLs',
    ],
  },
};

function validKqlOutput() {
  return {
    query: 'DeviceProcessEvents | where Timestamp > ago(1d) | summarize Count=count() by DeviceName',
    headers: {
      Title: 'Synthetic PowerShell hunt',
      Description: 'Synthetic case only',
      'Suspicious Behavior': 'PowerShell process activity',
      'MITRE ATT&CK': 'T1059.001',
      'Pyramid of Pain': 'TTP',
      'Kill Chain': 'Execution',
      'CTI URLs': 'https://example.invalid/cti',
    },
  };
}

test('KQL scorer accepts bounded contract-compliant query structure', () => {
  const result = normalized(scoreKqlCase(kqlCase, validKqlOutput()));
  assert.equal(result.score, 1);
  assert.equal(result.hardFail, false);
});

test('KQL forbidden dependency is a hard failure and missing structure lowers score', () => {
  const unsafe = validKqlOutput();
  unsafe.query += ' | where Source == "Sysmon"';
  const hard = normalized(scoreKqlCase(kqlCase, unsafe));
  assert.equal(hard.hardFail, true);
  assert.ok(hard.violations.includes('KQL_FORBIDDEN_TOKEN:sysmon'));

  const incomplete = validKqlOutput();
  incomplete.query = 'DeviceProcessEvents | where Timestamp > ago(1d)';
  delete incomplete.headers['CTI URLs'];
  const partial = normalized(scoreKqlCase(kqlCase, incomplete));
  assert.equal(partial.hardFail, false);
  assert.ok(partial.score < 1);
  assert.ok(partial.violations.includes('KQL_MISSING_REQUIRED_PATTERN:summarize'));
  assert.ok(partial.violations.includes('KQL_MISSING_HEADER:CTI URLs'));
});

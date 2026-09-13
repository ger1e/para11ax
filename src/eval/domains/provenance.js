import { roundScore } from '../canonical.js';

export const PROVENANCE_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });

function ratio(numerator, denominator) {
  return denominator === 0 ? 1 : numerator / denominator;
}

function finish({ score, hardFail, violations, metrics }) {
  return Object.freeze({
    score: roundScore(score),
    hardFail,
    violations: Object.freeze([...new Set(violations)].sort()),
    metrics: Object.freeze(metrics),
    humanReview: NO_REVIEW,
    scorerVersion: PROVENANCE_SCORER_VERSION,
  });
}

export function scoreProvenanceCase(evalCase, output) {
  const expectedClaims = evalCase?.expected?.claims;
  const criticalUnsupported = evalCase?.expected?.criticalUnsupportedClaimIds;
  if (!Array.isArray(expectedClaims) || !Array.isArray(criticalUnsupported)
      || !output || !Array.isArray(output.claims)) {
    return finish({
      score: 0,
      hardFail: true,
      violations: ['PROVENANCE_MALFORMED_OUTPUT'],
      metrics: { supportedClaims: 0, requiredClaims: 0, unsupportedClaims: 0, invalidEvidenceRefs: 0 },
    });
  }

  const expected = new Map(expectedClaims.map(claim => [claim.claimId, claim]));
  const criticalUnsupportedSet = new Set(criticalUnsupported);
  const seen = new Set();
  const violations = [];
  let supportedClaims = 0;
  let invalidEvidenceRefs = 0;
  let unsupportedClaims = 0;
  let hardFail = false;

  for (const claim of output.claims) {
    if (!claim || typeof claim.claimId !== 'string' || !Array.isArray(claim.evidenceIds)
        || !claim.evidenceIds.every(id => typeof id === 'string')) {
      return finish({
        score: 0,
        hardFail: true,
        violations: ['PROVENANCE_MALFORMED_OUTPUT'],
        metrics: { supportedClaims: 0, requiredClaims: expectedClaims.filter(item => item.required).length, unsupportedClaims: 0, invalidEvidenceRefs: 0 },
      });
    }
    if (seen.has(claim.claimId)) {
      violations.push(`PROVENANCE_DUPLICATE_CLAIM:${claim.claimId}`);
      continue;
    }
    seen.add(claim.claimId);

    const rule = expected.get(claim.claimId);
    if (!rule) {
      unsupportedClaims += 1;
      if (criticalUnsupportedSet.has(claim.claimId)) {
        violations.push(`PROVENANCE_CRITICAL_UNSUPPORTED:${claim.claimId}`);
        hardFail = true;
      } else {
        violations.push(`PROVENANCE_UNSUPPORTED_CLAIM:${claim.claimId}`);
      }
      continue;
    }

    const allowed = new Set(rule.allowedEvidenceIds);
    const uniqueEvidence = [...new Set(claim.evidenceIds)];
    const invalid = uniqueEvidence.filter(id => !allowed.has(id));
    for (const evidenceId of invalid) {
      violations.push(`PROVENANCE_INVALID_EVIDENCE_REF:${claim.claimId}:${evidenceId}`);
      invalidEvidenceRefs += 1;
    }
    const supported = uniqueEvidence.length > 0 && invalid.length === 0;
    if (supported) supportedClaims += 1;
    if (!supported && rule.critical) {
      violations.push(`PROVENANCE_CRITICAL_CLAIM_UNSUPPORTED:${claim.claimId}`);
      hardFail = true;
    }
  }

  const required = expectedClaims.filter(claim => claim.required);
  for (const claim of required) {
    if (!seen.has(claim.claimId)) {
      violations.push(`PROVENANCE_MISSING_REQUIRED_CLAIM:${claim.claimId}`);
      if (claim.critical) hardFail = true;
    }
  }

  const candidateCount = new Set(output.claims.map(claim => claim?.claimId).filter(id => typeof id === 'string')).size;
  const precision = ratio(supportedClaims, candidateCount);
  const recall = ratio(supportedClaims, required.length);
  const score = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return finish({
    score,
    hardFail,
    violations,
    metrics: {
      supportedClaims,
      requiredClaims: required.length,
      unsupportedClaims,
      invalidEvidenceRefs,
      precision: roundScore(precision),
      recall: roundScore(recall),
    },
  });
}

const BOTH = Object.freeze(['web', 'cli']);

function descriptor(id, tokens, usage, summary, { sideEffect = 'none', outputType = 'record' } = {}) {
  return Object.freeze({
    id,
    tokens: Object.freeze(tokens),
    aliases: Object.freeze([]),
    namespace: 'domain-investigation',
    surfaces: BOTH,
    auth: 'none',
    inputTypes: Object.freeze(['void', 'record']),
    outputType,
    egressClass: 'none',
    sideEffect,
    capabilities: Object.freeze([]),
    handler: id.replace('.', '-'),
    usage,
    summary,
  });
}

export const DOMAIN_INVESTIGATION_COMMAND_DESCRIPTORS = Object.freeze([
  descriptor('domain-investigation.build', ['domain-investigation', 'build'], 'domain-investigation build <gateway-enrichment-json>|--file <path>|--stdin', 'build a volatile Domain Investigation from canonical Evidence v2', { sideEffect: 'session' }),
  descriptor('domain-investigation.surface-import', ['domain-investigation', 'surface-import'], 'domain-investigation surface-import <surface-json>|--file <path>|--stdin', 'replace bounded external surface findings as operator context', { sideEffect: 'session' }),
  descriptor('domain-investigation.vulnerability-import', ['domain-investigation', 'vulnerability-import'], 'domain-investigation vulnerability-import <vulnerability-json>|--file <path>|--stdin', 'replace bounded vulnerability findings as operator context', { sideEffect: 'session' }),
  descriptor('domain-investigation.show', ['domain-investigation', 'show'], 'domain-investigation show', 'show the public Domain Investigation projection'),
  descriptor('domain-investigation.report', ['domain-investigation', 'report'], 'domain-investigation report', 'render the deterministic SOC report', { outputType: 'text' }),
  descriptor('domain-investigation.stix', ['domain-investigation', 'stix'], 'domain-investigation stix', 'render deterministic bounded STIX 2.1'),
  descriptor('domain-investigation.handoff', ['domain-investigation', 'handoff'], 'domain-investigation handoff', 'show the bounded next-agent handoff'),
  descriptor('domain-investigation.promotion-candidates', ['domain-investigation', 'promotion-candidates'], 'domain-investigation promotion-candidates', 'derive bounded zero-authority promotion candidates from imported operator context', { sideEffect: 'session', outputType: 'records' }),
  descriptor('domain-investigation.promote', ['domain-investigation', 'promote'], 'domain-investigation promote <approval-json>', 'approve one promotion candidate as an analyst attestation', { sideEffect: 'session' }),
  descriptor('domain-investigation.reject-promotion', ['domain-investigation', 'reject-promotion'], 'domain-investigation reject-promotion <decision-json>', 'reject one promotion candidate without granting authority', { sideEffect: 'session' }),
  descriptor('domain-investigation.revoke-promotion', ['domain-investigation', 'revoke-promotion'], 'domain-investigation revoke-promotion <decision-json>', 'revoke one active analyst attestation while preserving audit history', { sideEffect: 'session' }),
  descriptor('domain-investigation.graph', ['domain-investigation', 'graph'], 'domain-investigation graph', 'project current Domain Investigation authority state into the Evidence Graph', { outputType: 'graph' }),
  descriptor('domain-investigation.clear', ['domain-investigation', 'clear'], 'domain-investigation clear', 'clear volatile Domain Investigation state', { sideEffect: 'session' }),
]);

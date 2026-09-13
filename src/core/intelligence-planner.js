import { authorizeCapability } from './intelligence-policy.js';
import { rankProvidersForExecution } from './provider-priority.js';

const MAX_PIVOTS = 8;
const RELATION_TYPE_MAP = Object.freeze({ hostname: 'domain', nameserver: 'domain', mx: 'domain' });

function budgetRemaining(budget) {
  if (!budget || budget.deadlineExhausted || budget.callBudgetExhausted) return 0;
  const limit = Number.isSafeInteger(budget.providerCallLimit) ? budget.providerCallLimit : 0;
  const used = Number.isSafeInteger(budget.providerCalls) ? budget.providerCalls : 0;
  return Math.max(0, limit - used);
}

function targetType(relation) {
  const explicit = typeof relation?.targetType === 'string' ? relation.targetType.toLowerCase() : '';
  return RELATION_TYPE_MAP[explicit] ?? explicit;
}

function stableRelationKey(relation) {
  return `${targetType(relation)}\u0000${String(relation?.target ?? relation?.value ?? '')}`;
}

function allowedCandidates(candidates, type, authz) {
  const eligible = (Array.isArray(candidates) ? candidates : []).filter(candidate =>
    candidate
    && Array.isArray(candidate.types)
    && candidate.types.includes(type)
    && ['graph', 'search', 'sensitive'].includes(candidate.mode)
    && authorizeCapability({ adapter: candidate, requestedMode: candidate.mode, authz }).allowed
  );
  return rankProvidersForExecution({ providers: eligible, type }).map(entry => entry.adapter);
}

function pushUnique(output, seen, plan, limit) {
  if (output.length >= limit) return;
  const key = `${plan.provider}\u0000${plan.mode}\u0000${plan.input.type}\u0000${String(plan.input.value)}`;
  if (seen.has(key)) return;
  seen.add(key);
  output.push(Object.freeze({
    provider: plan.provider,
    mode: plan.mode,
    input: Object.freeze({ ...plan.input }),
    reason: plan.reason,
  }));
}

export function planPivots({
  indicator = null,
  type,
  evidence = [],
  relationships = [],
  candidates = [],
  authz,
  budget,
} = {}) {
  if (!Array.isArray(evidence) || evidence.length === 0) return Object.freeze([]);
  const remaining = Math.min(MAX_PIVOTS, budgetRemaining(budget));
  if (remaining < 1) return Object.freeze([]);

  const output = [];
  const seen = new Set();
  const relationGroups = new Map();
  for (const relation of [...(Array.isArray(relationships) ? relationships : [])].sort((a, b) => stableRelationKey(a).localeCompare(stableRelationKey(b)))) {
    const relType = targetType(relation);
    const value = relation?.target ?? relation?.value;
    if (!relType || typeof value !== 'string' || !value.trim()) continue;
    const key = `${relType}\u0000${value.trim()}`;
    if (!relationGroups.has(key)) relationGroups.set(key, { type: relType, value: value.trim() });
  }

  for (const pivot of relationGroups.values()) {
    const ranked = allowedCandidates(candidates, pivot.type, authz);
    if (!ranked.length) continue;
    const provider = ranked[0];
    pushUnique(output, seen, {
      provider: provider.name,
      mode: provider.mode,
      input: pivot,
      reason: 'relationship_pivot',
    }, remaining);
    if (output.length >= remaining) return Object.freeze(output);
  }

  if (type === 'cve') {
    const hasExploitMaturity = evidence.some(item => item?.observation?.kind === 'exploit_maturity');
    if (!hasExploitMaturity) {
      const cveCandidates = allowedCandidates(candidates, 'cve', authz)
        .filter(candidate => candidate.name === 'vulncheck' || candidate.semanticClassHints?.includes?.('exploit_maturity'));
      const provider = cveCandidates[0];
      if (provider) {
        const value = indicator ?? evidence.find(item => typeof item?.indicator === 'string')?.indicator ?? null;
        pushUnique(output, seen, {
          provider: provider.name,
          mode: provider.mode,
          input: { type: 'cve', value },
          reason: 'exploit_maturity_gap',
        }, remaining);
      }
    }
  }

  return Object.freeze(output);
}

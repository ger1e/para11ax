import { roundScore } from '../canonical.js';

export const CONTEXT_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });

function malformed() {
  return Object.freeze({
    score: 0,
    hardFail: true,
    violations: Object.freeze(['CONTEXT_MALFORMED_OUTPUT']),
    metrics: Object.freeze({
      usedTokens: 0,
      maxTokens: 0,
      requiredSelected: 0,
      requiredTotal: 0,
      durableRetention: 0,
      evictionQuality: 0,
    }),
    humanReview: NO_REVIEW,
    scorerVersion: CONTEXT_SCORER_VERSION,
  });
}

function scoreEvictionQuality(items, selected) {
  const nonDurable = items.filter(item => item.durable === false);
  let comparablePairs = 0;
  let inversions = 0;

  for (let left = 0; left < nonDurable.length; left += 1) {
    for (let right = left + 1; right < nonDurable.length; right += 1) {
      const a = nonDurable[left];
      const b = nonDurable[right];
      if (a.priority === b.priority) continue;
      const aSelected = selected.has(a.id);
      const bSelected = selected.has(b.id);
      if (aSelected === bSelected) continue;
      comparablePairs += 1;
      const higher = a.priority > b.priority ? a : b;
      const lower = higher === a ? b : a;
      if (selected.has(lower.id) && !selected.has(higher.id)) inversions += 1;
    }
  }

  if (comparablePairs === 0) return 1;
  return 1 - (inversions / comparablePairs);
}

export function scoreContextCase(evalCase, output) {
  const items = evalCase?.input?.items;
  const maxTokens = evalCase?.input?.maxTokens;
  const requiredIds = evalCase?.expected?.requiredIds;
  if (!Array.isArray(items) || !Number.isFinite(maxTokens) || maxTokens < 0
      || !Array.isArray(requiredIds) || !requiredIds.every(id => typeof id === 'string')
      || !output || !Array.isArray(output.selectedIds)
      || !output.selectedIds.every(id => typeof id === 'string')) {
    return malformed();
  }

  const byId = new Map();
  for (const item of items) {
    if (!item || typeof item.id !== 'string' || !Number.isFinite(item.tokens) || item.tokens < 0
        || typeof item.durable !== 'boolean' || !Number.isFinite(item.priority)) return malformed();
    if (byId.has(item.id)) return malformed();
    byId.set(item.id, item);
  }

  if (requiredIds.some(id => !byId.has(id))) return malformed();

  const selected = new Set(output.selectedIds);
  if (selected.size !== output.selectedIds.length) return malformed();
  const violations = [];
  let hardFail = false;
  let usedTokens = 0;

  for (const id of selected) {
    const item = byId.get(id);
    if (!item) {
      violations.push('CONTEXT_UNKNOWN_ID');
      hardFail = true;
      continue;
    }
    usedTokens += item.tokens;
  }

  let requiredSelected = 0;
  for (const id of requiredIds) {
    if (selected.has(id)) requiredSelected += 1;
    else {
      violations.push('CONTEXT_DURABLE_ITEM_LOST');
      hardFail = true;
    }
  }

  if (usedTokens > maxTokens) {
    violations.push('CONTEXT_BUDGET_EXCEEDED');
    hardFail = true;
  }

  const durableRetention = requiredIds.length === 0 ? 1 : requiredSelected / requiredIds.length;
  const evictionQuality = scoreEvictionQuality(items, selected);
  const score = (0.7 * durableRetention) + (0.3 * evictionQuality);

  return Object.freeze({
    score: roundScore(score),
    hardFail,
    violations: Object.freeze([...new Set(violations)].sort()),
    metrics: Object.freeze({
      usedTokens,
      maxTokens,
      requiredSelected,
      requiredTotal: requiredIds.length,
      durableRetention: roundScore(durableRetention),
      evictionQuality: roundScore(evictionQuality),
    }),
    humanReview: NO_REVIEW,
    scorerVersion: CONTEXT_SCORER_VERSION,
  });
}

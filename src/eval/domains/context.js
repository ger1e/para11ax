import { roundScore } from '../canonical.js';

export const CONTEXT_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });

function malformed() {
  return Object.freeze({
    score: 0,
    hardFail: true,
    violations: Object.freeze(['CONTEXT_MALFORMED_OUTPUT']),
    metrics: Object.freeze({ usedTokens: 0, maxTokens: 0, requiredSelected: 0, requiredTotal: 0 }),
    humanReview: NO_REVIEW,
    scorerVersion: CONTEXT_SCORER_VERSION,
  });
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
    if (!item || typeof item.id !== 'string' || !Number.isFinite(item.tokens) || item.tokens < 0) return malformed();
    if (byId.has(item.id)) return malformed();
    byId.set(item.id, item);
  }

  const selected = new Set(output.selectedIds);
  if (selected.size !== output.selectedIds.length) return malformed();
  const violations = [];
  let hardFail = false;
  let usedTokens = 0;
  let knownSelections = 0;

  for (const id of selected) {
    const item = byId.get(id);
    if (!item) {
      violations.push('CONTEXT_UNKNOWN_ID');
      hardFail = true;
      continue;
    }
    knownSelections += 1;
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

  const requiredRatio = requiredIds.length === 0 ? 1 : requiredSelected / requiredIds.length;
  const knownRatio = output.selectedIds.length === 0 ? 1 : knownSelections / output.selectedIds.length;
  const budgetScore = usedTokens <= maxTokens ? 1 : 0;

  return Object.freeze({
    score: roundScore((requiredRatio + knownRatio + budgetScore) / 3),
    hardFail,
    violations: Object.freeze([...new Set(violations)].sort()),
    metrics: Object.freeze({ usedTokens, maxTokens, requiredSelected, requiredTotal: requiredIds.length }),
    humanReview: NO_REVIEW,
    scorerVersion: CONTEXT_SCORER_VERSION,
  });
}

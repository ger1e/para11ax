const DURABLE_KINDS = new Set(['invariant', 'decision']);
const PRIORITY = Object.freeze({
  invariant: 1000,
  decision: 950,
  artifact_ref: 850,
  recent: 750,
  evidence: 650,
  tool_output: 300,
  scratch: 100,
});

function positiveInteger(value, field) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`invalid context budget: ${field}`);
  return value;
}

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

export function estimateTokens(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (!text) return 0;
  // Fallback only. Callers should pass provider-tokenized item.tokens when available.
  // 3.5 chars/token intentionally overestimates typical English/JSON to avoid silent overflow.
  return Math.ceil(text.length / 3.5);
}

export function planContextBudget({
  contextWindow,
  maxOutputTokens = 16_384,
  safetyReserveRatio = 0.05,
} = {}) {
  const window = positiveInteger(contextWindow, 'contextWindow');
  const output = positiveInteger(maxOutputTokens, 'maxOutputTokens');
  if (output >= window) throw new RangeError('invalid context budget: output exceeds context window');
  if (!Number.isFinite(safetyReserveRatio) || safetyReserveRatio < 0 || safetyReserveRatio > 0.2) throw new TypeError('invalid context budget: safetyReserveRatio');

  // Reasoning tokens are part of max output on current reasoning APIs. Reserving them
  // a second time wastes usable input context, so output is subtracted exactly once.
  const safetyReserveTokens = Math.floor(window * safetyReserveRatio);
  const inputBudgetTokens = window - output - safetyReserveTokens;
  if (inputBudgetTokens <= 0) throw new RangeError('invalid context budget: reserves exhaust context window');

  const allocations = {
    invariants: Math.floor(inputBudgetTokens * 0.12),
    decisions: Math.floor(inputBudgetTokens * 0.12),
    activeWork: Math.floor(inputBudgetTokens * 0.24),
    evidence: Math.floor(inputBudgetTokens * 0.30),
    toolOutput: Math.floor(inputBudgetTokens * 0.14),
  };
  allocations.scratch = inputBudgetTokens - Object.values(allocations).reduce((sum, value) => sum + value, 0);

  return Object.freeze({
    contextWindow: window,
    maxOutputTokens: output,
    reasoningBudgetPolicy: 'inside-max-output',
    safetyReserveTokens,
    inputBudgetTokens,
    allocations: Object.freeze(allocations),
    policy: 'durable-state-first-v1',
  });
}

function normalizeItem(item, index) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) throw new TypeError('invalid context item');
  const id = String(item.id ?? '').trim();
  const kind = String(item.kind ?? '').trim();
  const text = typeof item.text === 'string' ? item.text : JSON.stringify(item.text);
  if (!id || !Object.hasOwn(PRIORITY, kind) || !text) throw new TypeError('invalid context item');
  const tokens = item.tokens === undefined ? estimateTokens(text) : positiveInteger(item.tokens, 'item tokens');
  const recency = Number.isFinite(item.recency) ? Number(item.recency) : index;
  return { ...item, id, kind, text, tokens, recency, index };
}

export function selectContextItems(items, { maxTokens } = {}) {
  if (!Array.isArray(items)) throw new TypeError('invalid context budget: items');
  const limit = positiveInteger(maxTokens, 'maxTokens');
  const normalized = items.map(normalizeItem);
  const ids = normalized.map(item => item.id);
  if (new Set(ids).size !== ids.length) throw new TypeError('duplicate context item id');

  const durable = normalized.filter(item => DURABLE_KINDS.has(item.kind));
  const durableTokens = durable.reduce((sum, item) => sum + item.tokens, 0);
  if (durableTokens > limit) throw new RangeError('durable context exceeds budget');

  const chosen = new Set(durable.map(item => item.id));
  let usedTokens = durableTokens;
  const optional = normalized
    .filter(item => !DURABLE_KINDS.has(item.kind))
    .sort((left, right) => {
      const priorityDelta = PRIORITY[right.kind] - PRIORITY[left.kind];
      if (priorityDelta !== 0) return priorityDelta;
      const recencyDelta = right.recency - left.recency;
      if (recencyDelta !== 0) return recencyDelta;
      return left.index - right.index;
    });

  for (const item of optional) {
    if (usedTokens + item.tokens > limit) continue;
    chosen.add(item.id);
    usedTokens += item.tokens;
  }

  const selectedItems = normalized.filter(item => chosen.has(item.id)).sort((a, b) => a.index - b.index).map(({ index, ...item }) => item);
  const dropped = normalized.filter(item => !chosen.has(item.id)).sort((a, b) => a.index - b.index).map(({ index, ...item }) => item);
  const pressure = clamp(usedTokens / limit, 0, 1);
  return Object.freeze({
    items: Object.freeze(selectedItems),
    dropped: Object.freeze(dropped),
    usedTokens,
    maxTokens: limit,
    pressure,
    strategy: 'preserve-durable-evict-reproducible-v1',
  });
}

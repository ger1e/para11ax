const DEFAULT_MAX_INPUTS = 20;
const DEFAULT_PROVIDER_CALL_LIMIT = 200;
const DEFAULT_INDICATOR_CONCURRENCY = 3;

async function runPool(items, concurrency, worker) {
  const output = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      output[index] = await worker(items[index], index);
    }
  }));
  return output;
}

export async function runBatch({
  indicators,
  profile = 'standard',
  classify,
  enrichOne,
  callLimitFor,
  maxInputs = DEFAULT_MAX_INPUTS,
  providerCallLimit = DEFAULT_PROVIDER_CALL_LIMIT,
  indicatorConcurrency = DEFAULT_INDICATOR_CONCURRENCY,
  deadlineMs = 20_000,
  nowMs = () => Date.now(),
} = {}) {
  if (!Array.isArray(indicators) || indicators.length < 1 || indicators.length > maxInputs) throw new TypeError('invalid_batch_size');
  if (typeof classify !== 'function' || typeof enrichOne !== 'function' || typeof callLimitFor !== 'function') throw new TypeError('batch callbacks required');
  if (!Number.isInteger(providerCallLimit) || providerCallLimit < 1 || providerCallLimit > 200) throw new TypeError('invalid_batch_provider_call_limit');
  if (!Number.isInteger(indicatorConcurrency) || indicatorConcurrency < 1 || indicatorConcurrency > 3) throw new TypeError('invalid_batch_concurrency');
  if (!Number.isFinite(deadlineMs) || deadlineMs <= 0) throw new TypeError('invalid_batch_deadline');

  const started = nowMs();
  const deadlineAt = started + deadlineMs;
  const results = new Array(indicators.length);
  const unique = [];
  const keys = new Map();

  for (let index = 0; index < indicators.length; index += 1) {
    const input = indicators[index];
    try {
      const classified = classify(input);
      const key = `${classified.type}\u0000${classified.value}`;
      const existing = keys.get(key);
      if (existing) {
        existing.indices.push(index);
      } else {
        const item = { key, classified, firstIndex: index, indices: [index] };
        keys.set(key, item);
        unique.push(item);
      }
    } catch {
      results[index] = { index, input, status: 'invalid', requestStatus: 'rejected', error: 'invalid_indicator' };
    }
  }

  let availableCalls = providerCallLimit;
  let actualCalls = 0;
  let deadlineExhausted = false;
  let callBudgetExhausted = false;

  const completed = await runPool(unique, indicatorConcurrency, async item => {
    const now = nowMs();
    const remainingMs = deadlineAt - now;
    if (remainingMs <= 0) {
      deadlineExhausted = true;
      return { status: 'skipped', requestStatus: 'skipped', reason: 'batch_deadline_exhausted', classified: item.classified };
    }

    const desired = Math.max(1, Number(callLimitFor(item.classified.type)) || 1);
    const reserved = Math.min(desired, availableCalls);
    if (reserved <= 0) {
      callBudgetExhausted = true;
      return { status: 'skipped', requestStatus: 'skipped', reason: 'batch_provider_call_budget_exhausted', classified: item.classified };
    }
    availableCalls -= reserved;

    let enrichment;
    let consumptionKnown = true;
    try {
      enrichment = await enrichOne(item.classified, { profile, deadlineMs: remainingMs, callLimit: reserved });
    } catch {
      enrichment = null;
      consumptionKnown = false;
    }
    const used = consumptionKnown
      ? Math.max(0, Math.min(reserved, Number(enrichment?.budget?.providerCalls) || 0))
      : reserved;
    actualCalls += used;
    availableCalls += reserved - used;

    if (!enrichment) return { status: 'error', requestStatus: 'failed', reason: 'batch_enrichment_error', classified: item.classified };
    const enrichmentStatus = ['ok', 'partial', 'error'].includes(enrichment.status) ? enrichment.status : 'error';
    return {
      status: enrichmentStatus,
      requestStatus: enrichmentStatus === 'error' ? 'failed' : 'completed',
      classified: item.classified,
      enrichment,
    };
  });

  completed.forEach((work, uniqueIndex) => {
    const item = unique[uniqueIndex];
    for (const index of item.indices) {
      const duplicateOf = index === item.firstIndex ? undefined : item.firstIndex;
      const base = {
        index,
        input: indicators[index],
        canonical: item.classified.value,
        type: item.classified.type,
        status: work.status,
        requestStatus: work.requestStatus,
      };
      if (duplicateOf !== undefined) base.duplicateOf = duplicateOf;
      if (work.enrichment) base.enrichment = work.enrichment;
      if (work.reason) base.reason = work.reason;
      results[index] = base;
    }
  });

  return Object.freeze({
    profile,
    inputCount: indicators.length,
    uniqueIndicators: unique.length,
    durationMs: Math.max(0, nowMs() - started),
    budget: Object.freeze({
      providerCallLimit,
      providerCalls: actualCalls,
      deadlineMs,
      deadlineExhausted,
      callBudgetExhausted,
    }),
    results,
  });
}

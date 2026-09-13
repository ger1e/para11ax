import { planPivots } from './intelligence-planner.js';
import { runProvider } from './provider-runner.js';
import { normalizeEvidence } from './normalize.js';

const NEGATIVE_VERDICTS = new Set(['not_listed','not_found','no_result','no_association','clean','benign']);

function cacheKey(provider, type, value) {
  return `${provider}:${type}:${value}`;
}

function cacheTtl(adapter, result) {
  const verdict = String(result?.data?.verdict ?? '').toLowerCase();
  return NEGATIVE_VERDICTS.has(verdict) ? adapter.negativeCacheTtlMs : adapter.cacheTtlMs;
}

function cacheAllowed(adapter) {
  return adapter?.retentionClass !== 'no_store';
}

function frozenArray(items) {
  return Object.freeze(items.map(item => Object.freeze(item)));
}

export async function runIntelligencePivots({
  baseline,
  registry,
  authz,
  cache = null,
  now = () => new Date().toISOString(),
  nowMs = () => Date.now(),
  requestId = null,
  telemetry = null,
  context = {},
  candidates = null,
} = {}) {
  const baseBudget = baseline?.budget ?? {};
  const available = Math.max(0, Number(baseBudget.providerCallLimit ?? 0) - Number(baseBudget.providerCalls ?? 0));
  const deadlineMs = Math.max(0, Number(baseBudget.deadlineMs ?? 0));
  const baselineDurationMs = Math.max(0, Number(baseline?.durationMs ?? 0));
  const phaseDeadlineMs = Math.max(0, deadlineMs - baselineDurationMs);
  const phaseStartedAt = nowMs();
  const pivotBudget = {
    providerCalls: 0,
    providerCallLimit: available,
    deadlineMs,
    deadlineExhausted: Boolean(baseBudget.deadlineExhausted) || phaseDeadlineMs < 1,
    callBudgetExhausted: available < 1 || Boolean(baseBudget.callBudgetExhausted),
  };

  if (!baseline || baseline.status === 'error' || !registry || available < 1 || pivotBudget.deadlineExhausted) {
    return Object.freeze({ plans: Object.freeze([]), evidence: Object.freeze([]), relationships: Object.freeze([]), failures: Object.freeze([]), budget: Object.freeze(pivotBudget) });
  }

  const candidateList = Array.isArray(candidates)
    ? candidates
    : registry.values().filter(adapter => adapter.mode && adapter.mode !== 'enrich');

  const plans = planPivots({
    indicator: baseline.indicator,
    type: baseline.type,
    evidence: baseline.evidence,
    relationships: baseline.relationships,
    candidates: candidateList,
    authz,
    budget: { ...baseBudget, providerCallLimit: Number(baseBudget.providerCallLimit ?? 0) },
  });

  const evidence = [];
  const relationships = [];
  const failures = [];

  for (const plan of plans.slice(0, available)) {
    const elapsedMs = Math.max(0, nowMs() - phaseStartedAt);
    const remainingMs = Math.max(0, phaseDeadlineMs - elapsedMs);
    if (remainingMs < 1) {
      pivotBudget.deadlineExhausted = true;
      break;
    }

    const adapter = registry.get(plan.provider);
    if (!adapter) {
      failures.push({ provider: plan.provider, reason: 'provider_unavailable' });
      continue;
    }
    const value = plan.input.value ?? (plan.input.type === baseline.type ? baseline.indicator : null);
    if (typeof value !== 'string' || !value) {
      failures.push({ provider: plan.provider, reason: 'pivot_input_missing' });
      continue;
    }

    const canCache = cacheAllowed(adapter);
    const key = cacheKey(plan.provider, plan.input.type, value);
    let result = canCache ? cache?.get?.(key) : undefined;
    let cacheState = canCache && result !== undefined ? 'hit' : 'miss';
    if (result === undefined) {
      cacheState = 'miss';
      pivotBudget.providerCalls += 1;
      result = await runProvider(adapter, { value, type: plan.input.type }, {
        timeoutMs: Math.max(1, Math.min(adapter.timeoutMs, remainingMs)),
        now,
        nowMs,
        requestId,
        telemetry,
        context,
      });
      if (canCache && result?.ok) cache?.set?.(key, result, cacheTtl(adapter, result));
    }

    if (!result?.ok) {
      failures.push({ provider: plan.provider, ...(result?.failure ?? { reason: 'provider_error' }) });
      continue;
    }

    try {
      const item = normalizeEvidence(plan.provider, value, plan.input.type, result.data, {
        retrievedAt: result.retrievedAt,
        rawHash: result.rawHash,
        parserVersion: adapter.parserVersion ?? '1',
        cacheState,
        durationMs: cacheState === 'hit' ? 0 : result.durationMs,
        sourceRole: adapter.sourceRole ?? 'community',
        mode: adapter.mode,
        sensitivity: adapter.sensitivity,
        retentionClass: adapter.retentionClass,
        distribution: adapter.distribution,
      });
      evidence.push(item);
      for (const relation of item.relationships) {
        relationships.push({
          ...relation,
          provider: relation.provider ?? plan.provider,
          source: relation.source ?? value,
          sourceType: relation.sourceType ?? plan.input.type,
        });
      }
    } catch {
      failures.push({ provider: plan.provider, reason: 'evidence_normalization_error' });
    }
  }

  if (!pivotBudget.deadlineExhausted && Math.max(0, nowMs() - phaseStartedAt) >= phaseDeadlineMs) {
    pivotBudget.deadlineExhausted = true;
  }
  pivotBudget.callBudgetExhausted = pivotBudget.providerCalls >= pivotBudget.providerCallLimit && plans.length > pivotBudget.providerCalls;
  return Object.freeze({
    plans: Object.freeze([...plans]),
    evidence: frozenArray(evidence),
    relationships: frozenArray(relationships),
    failures: frozenArray(failures),
    budget: Object.freeze({ ...pivotBudget }),
  });
}

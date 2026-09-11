import { runProvider } from './provider-runner.js';
import { normalizeEvidence } from './normalize.js';
import { correlateEvidence } from './correlate.js';
import { buildDecisionSupport } from './decision-engine.js';
import { buildEvidenceGraph } from './evidence-graph.js';
import { buildGuidance } from './guidance.js';
import { buildIntelligenceKernel } from './intelligence-kernel.js';
import { IP_INTELLIGENCE_POLICY } from './intelligence-policy/ip.js';
import { runScheduledProviders } from './scheduler.js';
import { semanticClass } from './semantics.js';
import { EVIDENCE_SCHEMA_VERSION } from './version.js';

const NEGATIVE_SEMANTIC_VERDICTS = new Set(['not_listed', 'not_found', 'no_result', 'no_association', 'clean', 'benign']);
const MAX_LIMITATIONS = 16;

function cacheKey(provider, type, indicator) {
  return `${provider}:${type}:${indicator}`;
}

function cacheTtlFor(adapter, result) {
  if (!result?.ok) return null;
  const verdict = String(result?.data?.verdict ?? '').toLowerCase();
  return NEGATIVE_SEMANTIC_VERDICTS.has(verdict) ? adapter.negativeCacheTtlMs : adapter.cacheTtlMs;
}

function emptyHuntContext(indicator, type) {
  return { indicator, type, firstSeen: null, lastSeen: null, families: [], actors: [], sourceReferences: [] };
}

function providerSummary() {
  return { ok: 0, failed: 0, skipped: 0, cached: 0 };
}

function baseEnvelope({ requestId, indicator, type, queriedAt, gatewayVersion, profile, durationMs, budget, summary }) {
  return { schemaVersion: EVIDENCE_SCHEMA_VERSION, gatewayVersion, requestId, indicator, type, queriedAt, profile, durationMs, budget, providerSummary: summary };
}

function coverageObservationTypes(adapter, type) {
  const byType = adapter?.coverageObservationTypesByType;
  const typed = byType && typeof byType === 'object' ? byType[type] : null;
  if (Array.isArray(typed) && typed.length) return typed;
  return Array.isArray(adapter?.observationTypes) ? adapter.observationTypes : [];
}

function providerCoverageState(record) {
  if (!record || record.skipped) return 'skipped';
  if (record.result?.ok) return record.cacheState === 'hit' ? 'cached' : 'ok';
  return 'failed';
}

function providerCapabilityRecord(name, adapter, type, record) {
  if (!adapter?.types?.includes(type)) {
    return { provider: name, state: 'skipped', observationTypes: [], semanticClassHints: [], sourceRole: null };
  }
  const observationTypes = [...new Set(coverageObservationTypes(adapter, type).filter(value => typeof value === 'string' && value.length > 0))];
  const semanticClassHints = [...new Set(observationTypes.map(semanticClass))].sort();
  return {
    provider: name,
    state: providerCoverageState(record),
    observationTypes,
    semanticClassHints,
    sourceRole: adapter.sourceRole ?? 'community',
  };
}

function buildCoverage(providerNames, registry, type, records, summary, executedProviders) {
  const classProviders = new Map();
  const successfulClasses = new Set();
  const providerCapabilities = [];

  for (const name of providerNames) {
    const adapter = registry.get(name);
    const record = records.get(name);
    providerCapabilities.push(providerCapabilityRecord(name, adapter, type, record));
    if (!adapter?.types?.includes(type)) continue;

    const expectedClasses = [...new Set(coverageObservationTypes(adapter, type).map(semanticClass))];
    for (const cls of expectedClasses) {
      if (!classProviders.has(cls)) classProviders.set(cls, new Set());
      classProviders.get(cls).add(name);
    }

    if (!record?.result?.ok) continue;
    const actualKind = record.result?.data?.observationType;
    if (typeof actualKind === 'string' && actualKind) {
      successfulClasses.add(semanticClass(actualKind));
    } else if (expectedClasses.length === 1) {
      successfulClasses.add(expectedClasses[0]);
    }
  }

  const selected = providerNames.length;
  const lost = summary.failed + summary.skipped;
  const ratioLoss = selected > 0 && (lost / selected) > 0.25;
  const semanticLoss = [...classProviders.keys()].some(cls => !successfulClasses.has(cls));

  return {
    selected,
    executed: executedProviders.size,
    succeeded: summary.ok,
    failed: summary.failed,
    skipped: summary.skipped,
    materialLoss: ratioLoss || semanticLoss,
    providerCapabilities,
  };
}

function mergeLimitations(correlation, coverage) {
  const limitations = new Set(correlation?.limitations ?? []);
  if (coverage.succeeded > 0 && (coverage.failed > 0 || coverage.skipped > 0)) limitations.add('partial_provider_failure');
  if (coverage.materialLoss) limitations.add('material_coverage_loss');
  return [...limitations].sort().slice(0, MAX_LIMITATIONS);
}

function addLimitation(limitations, limitation) {
  return [...new Set([...(Array.isArray(limitations) ? limitations : []), limitation])].sort().slice(0, MAX_LIMITATIONS);
}

export async function enrich({
  indicator,
  type,
  providerNames,
  registry,
  cache,
  requestId,
  now = () => new Date().toISOString(),
  nowMs = () => Date.now(),
  gatewayVersion = '1.0.0',
  profile = 'standard',
  deadlineMs = 20_000,
  callLimit = Array.isArray(providerNames) ? Math.max(1, providerNames.length * 2) : 1,
  circuitBreaker = null,
  telemetry = null,
  context = {},
  projectIntelligence = buildIntelligenceKernel,
}) {
  const started = nowMs();
  telemetry?.emit?.({ event: 'request_start', requestId, type, profile, status: 'start', indicator });
  const budget = { providerCallLimit: callLimit, providerCalls: 0, deadlineMs, deadlineExhausted: false, callBudgetExhausted: false };
  const summary = providerSummary();

  if (!Array.isArray(providerNames) || providerNames.length === 0) {
    const queriedAt = now();
    const durationMs = Math.max(0, nowMs() - started);
    const rawCorrelation = correlateEvidence({ indicator, type, evidence: [], relationships: [], now: queriedAt });
    const coverage = { selected: 0, executed: 0, succeeded: 0, failed: 0, skipped: 0, materialLoss: false, providerCapabilities: [] };
    const limitations = rawCorrelation.limitations ?? [];
    const decision = buildDecisionSupport({ indicator, type, evidence: [], relationships: [], correlation: rawCorrelation, coverage, limitations, now: queriedAt });
    const correlation = { ...rawCorrelation, assessment: decision.assessment };
    telemetry?.emit?.({ event: 'budget', requestId, type, status: 'error', providerCalls: 0, providerCallLimit: callLimit, deadlineMs });
    telemetry?.emit?.({ event: 'request_complete', requestId, type, profile, status: 'error', durationMs, indicator });
    return {
      ...baseEnvelope({ requestId, indicator, type, queriedAt, gatewayVersion, profile, durationMs, budget, summary }),
      status: 'error', evidence: [], relationships: [], correlation, decision, coverage, limitations,
      failures: [{ provider: 'gateway', reason: 'no_configured_providers' }],
      huntContext: emptyHuntContext(indicator, type),
      meta: { gatewayVersion, cache: {}, providerHealth: {} },
    };
  }

  const evidence = [];
  const failures = [];
  const cacheMeta = {};
  const providerHealth = {};
  const relationships = [];
  const records = new Map();
  const pending = [];
  const executedProviders = new Set();

  for (const name of providerNames) {
    const adapter = registry.get(name);
    if (!adapter || !adapter.types.includes(type)) {
      records.set(name, { skipped: true, reason: 'unsupported_provider' });
      continue;
    }
    const key = cacheKey(name, type, indicator);
    const cached = cache?.get(key);
    if (cached !== undefined) {
      records.set(name, { result: cached, cacheState: 'hit', attempts: 0 });
      telemetry?.emit?.({ event: 'cache', requestId, type, provider: name, status: 'hit', cacheState: 'hit' });
    } else {
      pending.push(adapter);
      telemetry?.emit?.({ event: 'cache', requestId, type, provider: name, status: 'miss', cacheState: 'miss' });
    }
  }

  const scheduled = await runScheduledProviders({
    providers: pending,
    type,
    deadlineMs,
    callLimit,
    nowMs,
    circuitBreaker,
    execute: async (adapter, { timeoutMs }) => runProvider(adapter, { value: indicator, type }, { timeoutMs, now, nowMs, requestId, telemetry, context }),
  });
  budget.providerCalls = scheduled.calls;
  budget.deadlineExhausted = scheduled.deadlineExhausted;
  budget.callBudgetExhausted = scheduled.callBudgetExhausted;
  telemetry?.emit?.({ event: 'budget', requestId, type, status: scheduled.deadlineExhausted || scheduled.callBudgetExhausted ? 'exhausted' : 'within_limit', providerCalls: scheduled.calls, providerCallLimit: callLimit, deadlineMs, deadlineExhausted: scheduled.deadlineExhausted, callBudgetExhausted: scheduled.callBudgetExhausted });

  for (const item of scheduled.results) {
    if (item.skipped) {
      records.set(item.provider, { skipped: true, reason: item.reason, retryAfterMs: item.retryAfterMs ?? null, attempts: item.attempts });
      if (item.reason === 'circuit_open') telemetry?.emit?.({ event: 'circuit', requestId, type, provider: item.provider, status: 'open', reason: 'circuit_open', retryAfterMs: item.retryAfterMs ?? 0 });
      continue;
    }
    executedProviders.add(item.provider);
    records.set(item.provider, { result: item.result, cacheState: 'miss', attempts: item.attempts });
  }

  for (const name of providerNames) {
    const record = records.get(name);
    const adapter = registry.get(name);
    if (!record || record.skipped) {
      summary.skipped += 1;
      const reason = record?.reason ?? 'not_scheduled';
      failures.push({ provider: name, reason, ...(record?.retryAfterMs ? { retryAfterMs: record.retryAfterMs } : {}) });
      providerHealth[name] = reason;
      cacheMeta[name] = 'skipped';
      telemetry?.emit?.({ event: 'provider_outcome', requestId, type, provider: name, status: 'skipped', reason });
      continue;
    }

    const result = record.result;
    cacheMeta[name] = record.cacheState;
    if (result?.ok) {
      try {
        const item = normalizeEvidence(name, indicator, type, result.data, {
          retrievedAt: result.retrievedAt, rawHash: result.rawHash, parserVersion: adapter?.parserVersion ?? '1',
          cacheState: record.cacheState, durationMs: record.cacheState === 'hit' ? 0 : result.durationMs,
          sourceRole: adapter?.sourceRole ?? 'community',
        });
        evidence.push(item);
        relationships.push(...item.relationships.map(rel => ({ ...rel, provider: rel.provider ?? name })));

        const ttl = cacheTtlFor(adapter, result);
        if (record.cacheState !== 'hit' && ttl != null) cache?.set(cacheKey(name, type, indicator), result, ttl);

        summary.ok += 1;
        if (record.cacheState === 'hit') summary.cached += 1;
        providerHealth[name] = 'ok';
        telemetry?.emit?.({ event: 'provider_outcome', requestId, type, provider: name, status: 'success' });
      } catch {
        const failure = { reason: 'evidence_normalization_error' };
        const retrievedAt = result?.retrievedAt ?? now();
        cache?.delete?.(cacheKey(name, type, indicator));
        record.result = { ok: false, provider: name, failure, retrievedAt, durationMs: result?.durationMs ?? 0 };
        summary.failed += 1;
        providerHealth[name] = failure.reason;
        failures.push({ provider: name, ...failure, retrievedAt });
        telemetry?.emit?.({ event: 'provider_outcome', requestId, type, provider: name, status: 'failure', reason: failure.reason });
      }
    } else {
      summary.failed += 1;
      const failure = result?.failure ?? { reason: 'provider_error' };
      providerHealth[name] = failure.reason;
      failures.push({ provider: name, ...failure, retrievedAt: result?.retrievedAt ?? now() });
      const outcome = failure.reason === 'timeout' ? 'timeout' : failure.reason === 'rate_limited' ? 'rate_limited' : 'failure';
      telemetry?.emit?.({ event: 'provider_outcome', requestId, type, provider: name, status: outcome, reason: failure.reason });
    }
  }

  const status = evidence.length === 0 ? 'error' : failures.length ? 'partial' : 'ok';
  const references = [...new Set(evidence.flatMap(item => item.references))];
  const queriedAt = now();
  const rawCorrelation = correlateEvidence({ indicator, type, evidence, relationships, now: queriedAt });
  const coverage = buildCoverage(providerNames, registry, type, records, summary, executedProviders);
  let limitations = mergeLimitations(rawCorrelation, coverage);
  let baseCorrelation = { ...rawCorrelation, limitations };
  let intelligence;
  if (type === 'ip' && (status === 'ok' || status === 'partial')) {
    try {
      intelligence = projectIntelligence({
        indicator,
        type,
        evidence,
        relationships,
        correlation: baseCorrelation,
        coverage,
        now: queriedAt,
        policy: IP_INTELLIGENCE_POLICY,
      });
    } catch {
      limitations = addLimitation(limitations, 'intelligence_projection_unavailable');
      baseCorrelation = { ...rawCorrelation, limitations };
    }
  }
  const decision = buildDecisionSupport({
    indicator,
    type,
    evidence,
    relationships: baseCorrelation.relationships,
    correlation: baseCorrelation,
    coverage,
    limitations,
    now: queriedAt,
    intelligence,
  });
  const correlation = { ...baseCorrelation, assessment: decision.assessment };
  let evidenceGraph;
  let guidance;
  if (status === 'ok' || status === 'partial') {
    evidenceGraph = buildEvidenceGraph({
      indicator,
      type,
      evidence,
      relationships: correlation.relationships,
      correlation,
      decision,
    });
    guidance = buildGuidance({ decision, correlation, evidenceGraph, intelligence });
  }
  const durationMs = Math.max(0, nowMs() - started);
  telemetry?.emit?.({ event: 'request_complete', requestId, type, profile, status, durationMs, indicator });

  return {
    ...baseEnvelope({ requestId, indicator, type, queriedAt, gatewayVersion, profile, durationMs, budget, summary }),
    status, evidence, relationships: correlation.relationships, correlation, decision, coverage, limitations, failures,
    ...(intelligence ? { intelligence } : {}),
    ...(evidenceGraph ? { evidenceGraph, guidance } : {}),
    huntContext: {
      indicator, type,
      firstSeen: evidence.map(x => x.observation.firstSeen).filter(Boolean).sort()[0] ?? null,
      lastSeen: evidence.map(x => x.observation.lastSeen).filter(Boolean).sort().at(-1) ?? null,
      families: [...new Set(evidence.map(x => x.observation.malwareFamily).filter(Boolean))],
      actors: [...new Set(evidence.map(x => x.observation.actor).filter(Boolean))],
      sourceReferences: references,
    },
    meta: { gatewayVersion, cache: cacheMeta, providerHealth },
  };
}

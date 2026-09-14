import { runUserScannerScan } from '../user-scanner.js';
import { createTrustedAuthorizationContext } from './authorization-context.js';
import { authorizeCapability } from './intelligence-policy.js';
import { rankProvidersForExecution } from './provider-priority.js';
import { runProvider } from './provider-runner.js';
import { normalizeEvidence } from './normalize.js';

const MAX_DIRECT_PROVIDERS = 4;
const NEGATIVE_VERDICTS = new Set(['not_listed','not_found','no_result','no_association','clean','benign']);
const USERNAME_POLICY = Object.freeze({
  source: 'user-scanner',
  mode: 'search',
  fanoutEligible: false,
  sensitivity: 'pii',
  authorization: 'none',
  retentionClass: 'no_store',
  distribution: 'internal',
});

function cacheKey(provider, type, value) {
  return `intelligence:${provider}:${type}:${value}`;
}

function cacheTtl(adapter, result) {
  const verdict = String(result?.data?.verdict ?? '').toLowerCase();
  return NEGATIVE_VERDICTS.has(verdict) ? adapter.negativeCacheTtlMs : adapter.cacheTtlMs;
}

function cacheAllowed(adapter) {
  return adapter?.retentionClass !== 'no_store';
}

function providerState(adapter, env) {
  if (!adapter) return 'missing';
  if (adapter.active === false) return 'inactive';
  if (adapter.requiredEnv && !env?.[adapter.requiredEnv]) return 'unconfigured';
  return 'configured';
}

function scopeList(value) {
  if (value === undefined || value === null || value === '') return [];
  if (typeof value !== 'string') throw new TypeError('invalid server authorization scope');
  return value.split(',').map(item => item.trim()).filter(Boolean);
}

function serverAuthorizationContext(authz, env, mode) {
  if (authz?.trusted !== true) return authz;
  const ownedCidrs = [...new Set([...(authz.ownedCidrs ?? []), ...scopeList(env?.PARA11AX_OWNED_CIDRS)])];
  const verifiedDomains = [...new Set([...(authz.verifiedDomains ?? []), ...scopeList(env?.PARA11AX_VERIFIED_DOMAINS)])];
  return createTrustedAuthorizationContext({
    principal: authz.principal ?? undefined,
    caseId: authz.caseId ?? undefined,
    verifiedDomains,
    ownedCidrs,
    tenant: authz.tenant ?? undefined,
    explicitAnalysis: authz.explicitAnalysis === true,
    requestedMode: authz.requestedMode ?? mode,
  });
}

async function runUsernameSearch({ operation, mode, subject, env, nowMs, context }) {
  const scan = await runUserScannerScan({
    scanType: 'username',
    target: subject.value,
    crossScan: false,
    noNsfw: true,
  }, {
    env,
    fetchImpl: context.fetchImpl,
    nowMs,
    workloadToken: context.workloadToken ?? null,
  });

  if (scan.status < 200 || scan.status >= 300) {
    const error = new Error(scan.body?.error ?? 'user_scanner_unavailable');
    error.status = scan.status;
    throw error;
  }

  return Object.freeze({
    operation,
    mode,
    subject: Object.freeze({ ...subject }),
    policy: USERNAME_POLICY,
    scanner: Object.freeze(scan.body),
    providers: Object.freeze({
      selected: Object.freeze(['user-scanner']),
      executed: Object.freeze(['user-scanner']),
      denied: Object.freeze([]),
      unavailable: Object.freeze([]),
    }),
    evidence: Object.freeze([]),
    relationships: Object.freeze([]),
    failures: Object.freeze([]),
  });
}

export async function runIntelligenceMode({
  operation,
  mode,
  subject,
  registry,
  authz,
  env = {},
  cache = null,
  now = () => new Date().toISOString(),
  nowMs = () => Date.now(),
  requestId = null,
  telemetry = null,
  context = {},
  maxProviders = MAX_DIRECT_PROVIDERS,
} = {}) {
  if (!registry || !subject || typeof subject.type !== 'string' || typeof subject.value !== 'string') {
    throw new TypeError('intelligence execution requires registry and canonical subject');
  }
  if (!Number.isSafeInteger(maxProviders) || maxProviders < 1 || maxProviders > MAX_DIRECT_PROVIDERS) {
    throw new TypeError('maxProviders must be between 1 and 4');
  }

  if (operation === 'search' && mode === 'search' && subject.type === 'username') {
    return runUsernameSearch({ operation, mode, subject, env, nowMs, context });
  }

  const effectiveAuthz = serverAuthorizationContext(authz, env, mode);
  const selected = [];
  const denied = [];
  const unavailable = [];
  for (const adapter of registry.values()) {
    if (!Array.isArray(adapter.types) || !adapter.types.includes(subject.type) || adapter.mode !== mode) continue;
    const state = providerState(adapter, env);
    if (state !== 'configured') {
      unavailable.push(Object.freeze({ provider: adapter.name, state }));
      continue;
    }
    const decision = authorizeCapability({ adapter, requestedMode: mode, authz: effectiveAuthz, subject });
    if (!decision.allowed) {
      denied.push(Object.freeze({ provider: adapter.name, reason: decision.reason }));
      continue;
    }
    selected.push(adapter);
  }

  const ranked = rankProvidersForExecution({ providers: selected, type: subject.type })
    .slice(0, maxProviders)
    .map(entry => entry.adapter);
  const evidence = [];
  const relationships = [];
  const failures = [];
  const executed = [];

  for (const adapter of ranked) {
    const canCache = cacheAllowed(adapter);
    const key = cacheKey(adapter.name, subject.type, subject.value);
    let result = canCache ? cache?.get?.(key) : undefined;
    let cacheState = canCache && result !== undefined ? 'hit' : 'miss';
    if (result === undefined) {
      result = await runProvider(adapter, subject, {
        timeoutMs: adapter.timeoutMs,
        now,
        nowMs,
        requestId,
        telemetry,
        context,
      });
      if (canCache && result?.ok) cache?.set?.(key, result, cacheTtl(adapter, result));
    }
    executed.push(adapter.name);
    if (!result?.ok) {
      failures.push(Object.freeze({ provider: adapter.name, ...(result?.failure ?? { reason: 'provider_error' }) }));
      continue;
    }
    try {
      const item = normalizeEvidence(adapter.name, subject.value, subject.type, result.data, {
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
        relationships.push(Object.freeze({
          ...relation,
          provider: relation.provider ?? adapter.name,
          source: relation.source ?? subject.value,
          sourceType: relation.sourceType ?? subject.type,
        }));
      }
    } catch {
      failures.push(Object.freeze({ provider: adapter.name, reason: 'evidence_normalization_error' }));
    }
  }

  return Object.freeze({
    operation,
    mode,
    subject: Object.freeze({ ...subject }),
    providers: Object.freeze({
      selected: Object.freeze(ranked.map(adapter => adapter.name)),
      executed: Object.freeze(executed),
      denied: Object.freeze(denied),
      unavailable: Object.freeze(unavailable),
    }),
    evidence: Object.freeze(evidence),
    relationships: Object.freeze(relationships),
    failures: Object.freeze(failures),
  });
}

export const INTELLIGENCE_DIRECT_PROVIDER_LIMIT = MAX_DIRECT_PROVIDERS;

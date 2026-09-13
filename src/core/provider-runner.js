import { createHash } from 'node:crypto';
import { egressPolicyForAdapter, safeFetch } from './egress.js';
import { hasProviderExecutionAuthorization } from './execution-authorization.js';

function hashRaw(data) {
  return createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

function normalizeFailure(error, timedOut) {
  if (timedOut || error?.name === 'AbortError') return { reason: 'timeout' };
  if (error?.status === 429) return { reason: 'rate_limited', status: 429, retryAfter: error.retryAfter ?? null };
  if (Number.isInteger(error?.status)) return { reason: 'http_error', status: error.status };
  if (error?.code && String(error.code).startsWith('egress_')) return { reason: error.code };
  if (error?.message === 'provider_transport_error') return { reason: 'provider_transport_error' };
  return { reason: 'provider_error' };
}

export async function runProvider(adapter, input, {
  timeoutMs = 5000,
  now = () => new Date().toISOString(),
  nowMs = () => Date.now(),
  requestId = null,
  telemetry = null,
  context = {},
} = {}) {
  const started = nowMs();
  if (adapter?.authorization && adapter.authorization !== 'none'
      && !hasProviderExecutionAuthorization(context.executionAuthorization, adapter, input)) {
    const failure = { reason: 'authorization_required' };
    telemetry?.emit?.({ event: 'provider_complete', requestId, type: input?.type, provider: adapter?.name, status: 'failed', reason: failure.reason, durationMs: 0 });
    return { ok: false, provider: adapter?.name, failure, retrievedAt: now(), durationMs: 0 };
  }

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const policy = egressPolicyForAdapter(adapter);
  const upstreamFetch = context.fetchImpl ?? fetch;
  const guardedFetch = (url, options = {}) => safeFetch(url, policy, { ...options, fetchImpl: upstreamFetch });

  try {
    const data = await adapter.run(input, { ...context, signal: controller.signal, fetchImpl: guardedFetch });
    const retrievedAt = now();
    const durationMs = Math.max(0, nowMs() - started);
    telemetry?.emit?.({ event: 'provider_complete', requestId, type: input.type, provider: adapter.name, status: 'ok', durationMs });
    return { ok: true, provider: adapter.name, data, retrievedAt, rawHash: hashRaw(data), durationMs };
  } catch (error) {
    const failure = normalizeFailure(error, timedOut);
    const durationMs = Math.max(0, nowMs() - started);
    telemetry?.emit?.({ event: 'provider_complete', requestId, type: input.type, provider: adapter.name, status: 'failed', reason: failure.reason, durationMs });
    return { ok: false, provider: adapter.name, failure, retrievedAt: now(), durationMs };
  } finally {
    clearTimeout(timer);
  }
}

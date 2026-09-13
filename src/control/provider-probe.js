import { ALL_PROVIDERS } from '../providers/index.js';
import { runProvider } from '../core/provider-runner.js';

export const PROBE_SAMPLE_BY_TYPE = Object.freeze({
  ip: '8.8.8.8',
  domain: 'example.com',
  url: 'https://example.com/',
  hash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  certificate: 'cert-sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  cve: 'CVE-2021-44228',
  attack: 'T1059',
  asn: 'AS15169',
  cidr: '8.8.8.0/24',
  package: 'pkg:npm/lodash@4.17.21',
  'tls-fingerprint': 'ja3:72a589da586844d7f0818ce684948eea',
});

const STATUS_PRIORITY = Object.freeze({
  contract_error: 6,
  auth_failed: 5,
  rate_limited: 4,
  timeout: 3,
  upstream_error: 2,
  unconfigured: 1,
  ok: 0,
});

function inputsFor(provider) {
  return (Array.isArray(provider?.types) ? provider.types : []).map(type => ({
    type,
    value: PROBE_SAMPLE_BY_TYPE[type] ?? null,
  }));
}

function configured(env, name) {
  return typeof name === 'string' && typeof env?.[name] === 'string' && env[name].trim().length > 0;
}

function classifyFailure(failure) {
  const status = Number(failure?.status);
  if (status === 401 || status === 403) return 'auth_failed';
  if (failure?.reason === 'rate_limited' || status === 429) return 'rate_limited';
  if (failure?.reason === 'timeout' || status === 408 || status === 504) return 'timeout';
  if ((Number.isFinite(status) && status >= 500) || failure?.reason === 'provider_transport_error') return 'upstream_error';
  return 'contract_error';
}

function aggregateStatus(checks) {
  if (!checks.length) return 'contract_error';
  return checks.reduce((worst, check) =>
    (STATUS_PRIORITY[check.status] ?? STATUS_PRIORITY.contract_error) > (STATUS_PRIORITY[worst] ?? -1)
      ? check.status
      : worst, 'ok');
}

function providerResult(provider, checks) {
  const status = aggregateStatus(checks);
  const output = {
    provider: provider.name,
    status,
    checks: Object.freeze(checks),
  };
  if ((status === 'auth_failed' || status === 'unconfigured') && provider.requiredEnv) {
    output.credentialEnv = provider.requiredEnv;
  }
  if (checks.length === 1) {
    const [check] = checks;
    for (const key of ['type', 'latencyMs', 'httpStatus', 'observationType', 'verdict']) {
      if (check[key] !== undefined) output[key] = check[key];
    }
  } else {
    output.latencyMs = checks.reduce((sum, check) => sum + (Number(check.latencyMs) || 0), 0);
  }
  return Object.freeze(output);
}

async function probeInput(provider, input, { env, fetchImpl }) {
  if (!input?.value) return Object.freeze({ type: input?.type ?? 'unknown', status: 'contract_error' });
  const timeoutMs = Math.min(Math.max(Number(provider.timeoutMs) || 5000, 1000), 15000);
  const result = await runProvider(provider, Object.freeze({ type: input.type, value: input.value }), {
    timeoutMs,
    context: { env, fetchImpl },
  });
  if (!result.ok) {
    const status = Number(result.failure?.status);
    return Object.freeze({
      type: input.type,
      status: classifyFailure(result.failure),
      latencyMs: result.durationMs,
      ...(Number.isFinite(status) ? { httpStatus: status } : {}),
    });
  }

  const data = result.data;
  if (!data || typeof data !== 'object' || typeof data.observationType !== 'string' || !data.observationType) {
    return Object.freeze({ type: input.type, status: 'contract_error', latencyMs: result.durationMs });
  }
  return Object.freeze({
    type: input.type,
    status: 'ok',
    latencyMs: result.durationMs,
    observationType: data.observationType,
    verdict: typeof data.verdict === 'string' ? data.verdict : 'unknown',
  });
}

const defaultSleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function probeProvider(provider, {
  env = process.env,
  fetchImpl = fetch,
  sleep = defaultSleep,
} = {}) {
  const inputs = inputsFor(provider);
  if (!inputs.length) return providerResult(provider, [{ type: 'unknown', status: 'contract_error' }]);

  if (provider.requiredEnv && !configured(env, provider.requiredEnv)) {
    return providerResult(provider, inputs.map(input => Object.freeze({ type: input.type, status: 'unconfigured' })));
  }

  const checks = [];
  const intervalMs = Math.max(Number(provider.probeIntervalMs) || 0, 0);
  for (let index = 0; index < inputs.length; index += 1) {
    checks.push(await probeInput(provider, inputs[index], { env, fetchImpl }));
    if (intervalMs > 0 && index < inputs.length - 1) await sleep(intervalMs);
  }
  return providerResult(provider, checks);
}

export async function probeProviders({
  providers = ALL_PROVIDERS,
  env = process.env,
  fetchImpl = fetch,
  includeCredentialed = false,
  providerName = null,
} = {}) {
  const selected = providers
    .filter(provider => provider?.active !== false)
    .filter(provider => !providerName || provider.name === providerName)
    .filter(provider => includeCredentialed || !provider.requiredEnv);

  if (providerName && selected.length === 0) throw new Error('unknown or excluded provider');

  const output = [];
  for (const provider of selected) output.push(await probeProvider(provider, { env, fetchImpl }));
  return output;
}

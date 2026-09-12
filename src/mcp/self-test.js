import { createHmac, timingSafeEqual } from 'node:crypto';

import { securityHeaders } from '../core/http.js';
import { runFullMcpConformance } from './ga-conformance.js';
import { verifyGitHubActionsOidc } from './github-actions-oidc.js';
import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from './transport.js';

export const SELF_TEST_MESSAGE_PREFIX = 'para11ax-production-self-test:v1:';
const MAX_SKEW_SECONDS = 120;
const TEST_IP = '1.1.1.1';
const TEST_USERNAME = 'ger1e';
const MAX_PROVIDER_FAILURE_DIAGNOSTICS = 8;

function response(status, body, extraHeaders = {}) {
  return {
    status,
    headers: {
      ...securityHeaders(),
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      ...extraHeaders,
    },
    body,
  };
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
}

function queryValue(request, name) {
  const direct = request?.query?.[name];
  if (Array.isArray(direct)) return direct.length === 1 ? String(direct[0]) : null;
  if (direct !== undefined && direct !== null) return String(direct);
  try {
    return new URL(request?.url ?? '', 'https://para11ax.invalid').searchParams.get(name);
  } catch {
    return null;
  }
}

function validSignature(token, timestamp, supplied) {
  if (typeof token !== 'string' || !token) return false;
  if (!/^[a-f0-9]{64}$/i.test(String(supplied ?? ''))) return false;
  const expected = createHmac('sha256', token)
    .update(`${SELF_TEST_MESSAGE_PREFIX}${timestamp}`)
    .digest();
  const actual = Buffer.from(String(supplied), 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

async function authorizeSelfTest(request, { token, fetchImpl, nowMs }) {
  const authorization = String(headerValue(request?.headers, 'authorization') ?? '');
  if (authorization.startsWith('Bearer ')) {
    const oidc = authorization.slice(7).trim();
    if (oidc && await verifyGitHubActionsOidc(oidc, { fetchImpl, nowMs })) return 'github_oidc';
  }

  const tsRaw = queryValue(request, 'ts');
  const sig = queryValue(request, 'sig');
  if (!/^\d{10,13}$/.test(String(tsRaw ?? ''))) return null;
  const ts = Number(tsRaw);
  const nowSeconds = Math.floor(nowMs() / 1000);
  if (!Number.isSafeInteger(ts) || Math.abs(nowSeconds - ts) > MAX_SKEW_SECONDS || !validSignature(token, ts, sig)) return null;
  return 'hmac';
}

function mcpRequest(token, method, params, id, name = null, runtimeOidc = null) {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': method,
      ...(name ? { 'mcp-name': name } : {}),
      ...(runtimeOidc ? { 'x-vercel-oidc-token': runtimeOidc } : {}),
    },
    body: { jsonrpc: '2.0', id, method, params },
  };
}

function toolPayload(result, stage) {
  if (!result || result.status !== 200 || result.body?.error) throw new Error(`${stage}_transport_failed`);
  const payload = result.body?.result;
  if (!payload || payload.isError === true) throw new Error(`${stage}_failed`);
  return payload;
}

function boundedToolError(result, fallback) {
  const candidate = result?.body?.result?.structuredContent?.error;
  if (typeof candidate === 'string' && /^[a-z0-9_:-]{1,64}$/i.test(candidate)) return candidate;
  return fallback;
}

function classifyToolFailure(result) {
  if (!result) return 'transport_exception';
  if (result.status !== 200) return 'transport_http_error';
  if (result.body?.error) return 'rpc_error';
  const payload = result.body?.result;
  if (!payload) return 'missing_result';
  if (payload.isError === true) return 'tool_error';
  return 'shape_error';
}

function evidenceCount(enrichment) {
  if (Array.isArray(enrichment?.evidence)) return enrichment.evidence.length;
  if (Array.isArray(enrichment?.evidenceV2?.observations)) return enrichment.evidenceV2.observations.length;
  if (Array.isArray(enrichment?.evidenceV2?.items)) return enrichment.evidenceV2.items.length;
  if (Array.isArray(enrichment?.['evidence-v2']?.observations)) return enrichment['evidence-v2'].observations.length;
  if (Array.isArray(enrichment?.['evidence-v2']?.items)) return enrichment['evidence-v2'].items.length;
  return 0;
}

function failureCount(enrichment) {
  if (Array.isArray(enrichment?.failures)) return enrichment.failures.length;
  const failed = enrichment?.coverage?.failed;
  return Number.isSafeInteger(failed) && failed >= 0 ? failed : 0;
}

function boundedProviderFailures(enrichment) {
  if (!Array.isArray(enrichment?.failures)) return [];
  return enrichment.failures.slice(0, MAX_PROVIDER_FAILURE_DIAGNOSTICS).map(failure => {
    const provider = typeof failure?.provider === 'string' && /^[a-z0-9][a-z0-9._-]{0,63}$/i.test(failure.provider)
      ? failure.provider
      : 'unknown';
    const reason = typeof failure?.reason === 'string' && /^[a-z0-9][a-z0-9_:-]{0,63}$/i.test(failure.reason)
      ? failure.reason
      : 'provider_error';
    return { provider, reason };
  });
}

export function createSignedProductionSelfTestHandler({
  env = process.env,
  fetchImpl = fetch,
  now = () => new Date().toISOString(),
  nowMs = () => Date.now(),
  mcpHandler = null,
} = {}) {
  const token = env.PARA11AX_TOKEN;
  const mcp = mcpHandler ?? createMcpHttpHandler({ env, fetchImpl, now, nowMs });

  return async function handleSignedProductionSelfTest(request) {
    if (request?.method !== 'GET') return response(405, { error: 'method_not_allowed' }, { allow: 'GET' });
    if (typeof token !== 'string' || !token) return response(503, { error: 'self_test_unconfigured' });

    const mode = queryValue(request, 'mode');
    if (mode !== null && mode !== 'full') return response(400, { error: 'invalid_self_test_mode' });
    const fullMode = mode === 'full';

    const authorization = await authorizeSelfTest(request, { token, fetchImpl, nowMs });
    if (!authorization) return response(401, { error: 'unauthorized' });
    const runtimeOidc = String(headerValue(request?.headers, 'x-vercel-oidc-token') ?? '').trim() || null;

    let tools;
    try {
      const catalogResult = await mcp(mcpRequest(token, 'tools/list', {}, 1, null, runtimeOidc));
      const catalog = toolPayload(catalogResult, 'mcp_catalog');
      tools = Array.isArray(catalog.tools) ? catalog.tools : [];
      const names = new Set(tools.map(tool => tool?.name).filter(Boolean));
      if (!names.has('para11ax_enrich') || !names.has('para11ax_user_scan')) throw new Error('mcp_catalog_failed');
    } catch (error) {
      const code = ['mcp_catalog_transport_failed', 'mcp_catalog_failed'].includes(error?.message)
        ? error.message
        : 'self_test_failed';
      return response(502, { status: 'fail', error: code });
    }

    let enrichmentOk = false;
    let enrichmentSummary;
    let enrichmentValue = null;
    let enrichResult;
    try {
      enrichResult = await mcp(mcpRequest(token, 'tools/call', {
        name: 'para11ax_enrich',
        arguments: { indicator: TEST_IP, profile: 'fast' },
      }, 2, 'para11ax_enrich', runtimeOidc));
      const enrichTool = toolPayload(enrichResult, 'mcp_enrichment');
      const enrichment = enrichTool.structuredContent?.enrichment;
      if (!enrichment || typeof enrichment !== 'object' || Array.isArray(enrichment)) throw new Error('mcp_enrichment_failed');
      enrichmentValue = enrichment;
      enrichmentOk = true;
      enrichmentSummary = {
        target: TEST_IP,
        profile: 'fast',
        status: String(enrichment.status ?? 'unknown').slice(0, 32),
        evidenceCount: evidenceCount(enrichment),
        failureCount: failureCount(enrichment),
        providerFailures: boundedProviderFailures(enrichment),
      };
    } catch {
      enrichmentSummary = {
        target: TEST_IP,
        profile: 'fast',
        status: 'fail',
        error: boundedToolError(enrichResult, 'mcp_enrichment_failed'),
      };
    }

    let userScannerOk = false;
    let userScannerSummary;
    let userScannerValue = null;
    let userResult;
    try {
      userResult = await mcp(mcpRequest(token, 'tools/call', {
        name: 'para11ax_user_scan',
        arguments: { scanType: 'username', target: TEST_USERNAME, crossScan: false, noNsfw: true },
      }, 3, 'para11ax_user_scan', runtimeOidc));
      const userTool = toolPayload(userResult, 'mcp_user_scanner');
      const scan = userTool.structuredContent?.result;
      const summary = scan?.summary;
      if (!summary || typeof summary !== 'object' || Array.isArray(summary)) throw new Error('mcp_user_scanner_failed');
      userScannerValue = {
        totalScanned: Number(summary.totalScanned ?? 0),
        found: Number(summary.found ?? 0),
        notFound: Number(summary.notFound ?? 0),
        errors: Number(summary.errors ?? 0),
        skipped: Number(summary.skipped ?? 0),
      };
      userScannerOk = true;
      userScannerSummary = {
        target: TEST_USERNAME,
        ...userScannerValue,
        durationMs: Number(scan.durationMs ?? 0),
      };
    } catch {
      userScannerSummary = {
        target: TEST_USERNAME,
        status: 'fail',
        error: boundedToolError(userResult, 'mcp_user_scanner_failed'),
      };
    }

    let diagnostics;
    if (!enrichmentOk && !userScannerOk) {
      enrichmentSummary.failureClass = classifyToolFailure(enrichResult);
      userScannerSummary.failureClass = classifyToolFailure(userResult);
      let genericToolCall = 'fail';
      try {
        const probeResult = await mcp(mcpRequest(token, 'tools/call', {
          name: 'para11ax_command',
          arguments: { commandId: 'intel.validate', args: [TEST_IP] },
        }, 4, 'para11ax_command', runtimeOidc));
        const probe = toolPayload(probeResult, 'mcp_generic_probe');
        if (probe.structuredContent?.command === 'intel.validate') genericToolCall = 'pass';
      } catch {}
      diagnostics = {
        genericToolCall,
        userScannerUrlConfigured: Boolean(env.PARA11AX_USER_SCANNER_URL),
        userScannerTokenConfigured: Boolean(env.PARA11AX_USER_SCANNER_TOKEN),
      };
    }

    let conformance;
    if (fullMode) {
      let nextId = 10;
      const invoke = async (name, args = {}) => {
        const result = await mcp(mcpRequest(token, 'tools/call', {
          name,
          arguments: args,
        }, nextId++, name, runtimeOidc));
        const payload = toolPayload(result, `mcp_ga_${name}`);
        return payload.structuredContent;
      };
      conformance = await runFullMcpConformance({
        invoke,
        enrichment: enrichmentValue,
        userScanner: userScannerValue,
        now,
      });
    }

    const baselineStatus = enrichmentOk && userScannerOk ? 'pass' : enrichmentOk || userScannerOk ? 'partial' : 'fail';
    const status = fullMode && conformance?.status !== 'pass' ? 'fail' : baselineStatus;

    return response(200, {
      status,
      authorization,
      deploymentSha: typeof env.VERCEL_GIT_COMMIT_SHA === 'string' && /^[0-9a-f]{40}$/i.test(env.VERCEL_GIT_COMMIT_SHA)
        ? env.VERCEL_GIT_COMMIT_SHA.toLowerCase()
        : null,
      mcp: { authenticated: true, toolCount: tools.length },
      enrichment: enrichmentSummary,
      userScanner: userScannerSummary,
      ...(conformance ? { conformance } : {}),
      ...(diagnostics ? { diagnostics } : {}),
    });
  };
}

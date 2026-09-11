import { createHmac, timingSafeEqual } from 'node:crypto';

import { securityHeaders } from '../core/http.js';
import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from './transport.js';

export const SELF_TEST_MESSAGE_PREFIX = 'para11ax-production-self-test:v1:';
const MAX_SKEW_SECONDS = 120;
const TEST_IP = '1.1.1.1';
const TEST_USERNAME = 'ger1e';

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

function mcpRequest(token, method, params, id, name = null) {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': method,
      ...(name ? { 'mcp-name': name } : {}),
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

    const tsRaw = queryValue(request, 'ts');
    const sig = queryValue(request, 'sig');
    if (!/^\d{10,13}$/.test(String(tsRaw ?? ''))) return response(401, { error: 'unauthorized' });
    const ts = Number(tsRaw);
    const nowSeconds = Math.floor(nowMs() / 1000);
    if (!Number.isSafeInteger(ts) || Math.abs(nowSeconds - ts) > MAX_SKEW_SECONDS || !validSignature(token, ts, sig)) {
      return response(401, { error: 'unauthorized' });
    }

    try {
      const catalogResult = await mcp(mcpRequest(token, 'tools/list', {}, 1));
      const catalog = toolPayload(catalogResult, 'mcp_catalog');
      const tools = Array.isArray(catalog.tools) ? catalog.tools : [];
      const names = new Set(tools.map(tool => tool?.name).filter(Boolean));
      if (!names.has('para11ax_enrich') || !names.has('para11ax_user_scan')) throw new Error('mcp_catalog_failed');

      const enrichResult = await mcp(mcpRequest(token, 'tools/call', {
        name: 'para11ax_enrich',
        arguments: { indicator: TEST_IP, profile: 'fast' },
      }, 2, 'para11ax_enrich'));
      const enrichTool = toolPayload(enrichResult, 'mcp_enrichment');
      const enrichment = enrichTool.structuredContent?.enrichment;
      if (!enrichment || typeof enrichment !== 'object' || Array.isArray(enrichment)) throw new Error('mcp_enrichment_failed');

      const userResult = await mcp(mcpRequest(token, 'tools/call', {
        name: 'para11ax_user_scan',
        arguments: { scanType: 'username', target: TEST_USERNAME, crossScan: false, noNsfw: true },
      }, 3, 'para11ax_user_scan'));
      const userTool = toolPayload(userResult, 'mcp_user_scanner');
      const scan = userTool.structuredContent?.result;
      const summary = scan?.summary;
      if (!summary || typeof summary !== 'object' || Array.isArray(summary)) throw new Error('mcp_user_scanner_failed');

      return response(200, {
        status: 'pass',
        mcp: { authenticated: true, toolCount: tools.length },
        enrichment: {
          target: TEST_IP,
          profile: 'fast',
          status: String(enrichment.status ?? 'unknown').slice(0, 32),
          evidenceCount: evidenceCount(enrichment),
          failureCount: failureCount(enrichment),
        },
        userScanner: {
          target: TEST_USERNAME,
          totalScanned: Number(summary.totalScanned ?? 0),
          found: Number(summary.found ?? 0),
          notFound: Number(summary.notFound ?? 0),
          errors: Number(summary.errors ?? 0),
          skipped: Number(summary.skipped ?? 0),
          durationMs: Number(scan.durationMs ?? 0),
        },
      });
    } catch (error) {
      const known = new Set([
        'mcp_catalog_transport_failed', 'mcp_catalog_failed',
        'mcp_enrichment_transport_failed', 'mcp_enrichment_failed',
        'mcp_user_scanner_transport_failed', 'mcp_user_scanner_failed',
      ]);
      const code = known.has(error?.message) ? error.message : 'self_test_failed';
      return response(502, { status: 'fail', error: code });
    }
  };
}

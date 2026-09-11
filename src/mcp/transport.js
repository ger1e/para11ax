import {
  createMcpHttpHandler as createMcpCoreHandler,
  MCP_PROTOCOL_VERSION,
  MCP_TOOLS,
} from './server.js';
import { securityHeaders } from '../core/http.js';
import { applyChatGptToolMetadata } from './chatgpt-tool-metadata.js';

applyChatGptToolMetadata(MCP_TOOLS);

const LIST_TTL_MS = 300_000;
const HEADER_MISMATCH = -32001;

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
}

function requestBody(request) {
  if (request?.body && typeof request.body === 'object' && !Array.isArray(request.body)) return request.body;
  if (typeof request?.body !== 'string') return null;
  try {
    const parsed = JSON.parse(request.body);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function errorBody(id, message) {
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    error: { code: HEADER_MISMATCH, message },
  };
}

function rejectHeaderMismatch(body, message) {
  return {
    status: 400,
    headers: {
      ...securityHeaders(),
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
    },
    body: errorBody(body?.id, message),
  };
}

function validateModernRoutingHeaders(request, body) {
  if (headerValue(request?.headers, 'mcp-protocol-version') !== MCP_PROTOCOL_VERSION) return null;
  if (!body || typeof body.method !== 'string') return null;

  const methodHeader = headerValue(request.headers, 'mcp-method');
  if (methodHeader === undefined || String(methodHeader) !== body.method) {
    return rejectHeaderMismatch(body, 'Header mismatch: Mcp-Method must match the JSON-RPC method');
  }

  if (body.method === 'tools/call') {
    const bodyName = body.params?.name;
    const nameHeader = headerValue(request.headers, 'mcp-name');
    if (typeof bodyName !== 'string' || nameHeader === undefined || String(nameHeader) !== bodyName) {
      return rejectHeaderMismatch(body, 'Header mismatch: Mcp-Name must match params.name');
    }
  }
  return null;
}

function complete(result) {
  return result && typeof result === 'object' && !Array.isArray(result)
    ? { resultType: 'complete', ...result }
    : result;
}

function normalizeModernResult(request, response) {
  if (headerValue(request?.headers, 'mcp-protocol-version') !== MCP_PROTOCOL_VERSION) return response;
  if (!response?.body || typeof response.body !== 'object' || response.body.error || !response.body.result) return response;

  const body = requestBody(request);
  if (!body) return response;
  const next = structuredClone(response);

  if (body.method === 'server/discover') {
    const result = { ...next.body.result };
    delete result.protocolVersion;
    next.body.result = {
      resultType: 'complete',
      supportedVersions: [MCP_PROTOCOL_VERSION],
      capabilities: result.capabilities ?? { tools: { listChanged: false } },
      serverInfo: result.serverInfo,
      ...(result.instructions ? { instructions: result.instructions } : {}),
      ttlMs: LIST_TTL_MS,
      cacheScope: 'private',
    };
    return next;
  }

  if (body.method === 'tools/list') {
    next.body.result = {
      ...complete(next.body.result),
      ttlMs: LIST_TTL_MS,
      cacheScope: 'private',
    };
    return next;
  }

  next.body.result = complete(next.body.result);
  return next;
}

export function createMcpHttpHandler(options = {}) {
  const core = createMcpCoreHandler(options);
  return async function handleMcpTransport(request) {
    const body = requestBody(request);
    const headerFailure = validateModernRoutingHeaders(request, body);
    if (headerFailure) return headerFailure;
    return normalizeModernResult(request, await core(request));
  };
}

export { MCP_PROTOCOL_VERSION, MCP_TOOLS };

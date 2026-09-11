import {
  createMcpHttpHandler as createMcpCoreHandler,
  MCP_PROTOCOL_VERSION,
  MCP_TOOLS,
} from './server.js';
import { securityHeaders } from '../core/http.js';
import { GATEWAY_VERSION } from '../core/version.js';
import { applyChatGptToolMetadata } from './chatgpt-tool-metadata.js';

applyChatGptToolMetadata(MCP_TOOLS);

const LIST_TTL_MS = 300_000;
const LEGACY_PROTOCOL_VERSION = '2025-06-18';
const HEADER_MISMATCH = -32020;
const UNSUPPORTED_PROTOCOL_VERSION = -32022;
const SERVER_INFO_META_KEY = 'io.modelcontextprotocol/serverInfo';
const PROTOCOL_VERSION_META_KEY = 'io.modelcontextprotocol/protocolVersion';
const MCP_SERVER_BRAND = Object.freeze({
  title: 'PARA11AX',
  websiteUrl: 'https://para11ax.vercel.app/',
  icons: Object.freeze([Object.freeze({
    src: 'https://para11ax.vercel.app/assets/brand/para11ax-mark.svg',
    mimeType: 'image/svg+xml',
    sizes: Object.freeze(['any']),
  })]),
});

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

function bodyProtocolVersion(body) {
  return body?.params?._meta?.[PROTOCOL_VERSION_META_KEY];
}

function rpcErrorBody(id, code, message, data) {
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    error: {
      code,
      message,
      ...(data === undefined ? {} : { data }),
    },
  };
}

function rejectModernRequest(body, code, message, data) {
  return {
    status: 400,
    headers: {
      ...securityHeaders(),
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
    },
    body: rpcErrorBody(body?.id, code, message, data),
  };
}

function rejectHeaderMismatch(body, message) {
  return rejectModernRequest(body, HEADER_MISMATCH, message);
}

function rejectUnsupportedProtocol(body, requested) {
  return rejectModernRequest(body, UNSUPPORTED_PROTOCOL_VERSION, 'Unsupported MCP protocol version', {
    supported: [MCP_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION],
    requested,
  });
}

function validateModernRoutingHeaders(request, body) {
  if (!body || typeof body.method !== 'string') return null;

  const protocolHeader = headerValue(request?.headers, 'mcp-protocol-version');
  const protocolEnvelope = bodyProtocolVersion(body);
  const headerVersion = protocolHeader === undefined ? undefined : String(protocolHeader);
  const envelopeVersion = protocolEnvelope === undefined ? undefined : String(protocolEnvelope);

  if (headerVersion !== undefined && ![MCP_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION].includes(headerVersion)) {
    return rejectUnsupportedProtocol(body, headerVersion);
  }
  if (headerVersion === undefined && envelopeVersion !== undefined
    && ![MCP_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION].includes(envelopeVersion)) {
    return rejectUnsupportedProtocol(body, envelopeVersion);
  }

  const modernHeader = headerVersion === MCP_PROTOCOL_VERSION;
  const modernEnvelope = envelopeVersion === MCP_PROTOCOL_VERSION;

  // The modern era is self-identifying. If either side claims 2026-07-28,
  // require the HTTP/body mirror to agree rather than silently downgrading.
  if (modernEnvelope && !modernHeader) {
    return rejectHeaderMismatch(body, 'Header mismatch: MCP-Protocol-Version must mirror the request _meta protocol version');
  }
  if (!modernHeader) return null;
  if (envelopeVersion !== undefined && envelopeVersion !== MCP_PROTOCOL_VERSION) {
    return rejectHeaderMismatch(body, 'Header mismatch: MCP-Protocol-Version must match the request _meta protocol version');
  }

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

function brandedServerInfo(serverInfo = {}) {
  return {
    name: 'para11ax',
    version: GATEWAY_VERSION,
    ...serverInfo,
    ...MCP_SERVER_BRAND,
    icons: MCP_SERVER_BRAND.icons.map(icon => ({ ...icon, sizes: [...icon.sizes] })),
  };
}

function applyServerBranding(body, response) {
  if (!['initialize', 'server/discover'].includes(body?.method)) return response;
  if (!response?.body || typeof response.body !== 'object' || response.body.error || !response.body.result) return response;
  const next = structuredClone(response);
  next.body.result.serverInfo = brandedServerInfo(next.body.result.serverInfo);
  return next;
}

function isModernRequest(request, body) {
  return headerValue(request?.headers, 'mcp-protocol-version') === MCP_PROTOCOL_VERSION
    || bodyProtocolVersion(body) === MCP_PROTOCOL_VERSION;
}

function stampModernServerInfo(result) {
  const serverInfo = brandedServerInfo(result?.serverInfo);
  return {
    ...result,
    _meta: {
      ...(result?._meta && typeof result._meta === 'object' ? result._meta : {}),
      [SERVER_INFO_META_KEY]: serverInfo,
    },
  };
}

function normalizeModernResult(request, response) {
  if (!response?.body || typeof response.body !== 'object' || response.body.error || !response.body.result) return response;

  const body = requestBody(request);
  if (!body || !isModernRequest(request, body)) return response;
  const next = structuredClone(response);
  const stamped = stampModernServerInfo(next.body.result);

  if (body.method === 'server/discover') {
    const result = { ...stamped };
    delete result.protocolVersion;
    delete result.serverInfo;
    next.body.result = {
      resultType: 'complete',
      supportedVersions: [MCP_PROTOCOL_VERSION],
      capabilities: result.capabilities ?? { tools: { listChanged: false } },
      ...(result.instructions ? { instructions: result.instructions } : {}),
      _meta: result._meta,
      ttlMs: LIST_TTL_MS,
      cacheScope: 'private',
    };
    return next;
  }

  if (body.method === 'tools/list') {
    next.body.result = {
      ...complete(stamped),
      ttlMs: LIST_TTL_MS,
      cacheScope: 'private',
    };
    return next;
  }

  next.body.result = complete(stamped);
  return next;
}

export function createMcpHttpHandler(options = {}) {
  const core = createMcpCoreHandler(options);
  return async function handleMcpTransport(request) {
    const body = requestBody(request);
    const headerFailure = validateModernRoutingHeaders(request, body);
    if (headerFailure) return headerFailure;
    const branded = applyServerBranding(body, await core(request));
    return normalizeModernResult(request, branded);
  };
}

export { MCP_PROTOCOL_VERSION, MCP_TOOLS };

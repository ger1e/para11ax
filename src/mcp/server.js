import { buildAgentExecutionPlan } from '../core/agent-execution-plan.js';
import { executeDomainInvestigationCommand } from '../core/domain-investigation-command-adapter.js';
import { INVESTIGATION_LIMITS } from '../core/investigation/index.js';
import { securityHeaders } from '../core/http.js';
import { verifyMcpAuthorization } from './oauth.js';
import {
  MCP_PROTOCOL_VERSION,
  MCP_TOOLS as RUNTIME_MCP_TOOLS,
  createMcpHttpHandler as createRuntimeMcpHttpHandler,
} from './server-runtime.js';

export { MCP_PROTOCOL_VERSION };

const MAX_BODY_BYTES = 128 * 1024;
const MAX_LARGE_BODY_BYTES = (2 * INVESTIGATION_LIMITS.bundleBytes) + (64 * 1024);
const DOMAIN_ACTIONS = Object.freeze([
  'build', 'surface_import', 'vulnerability_import', 'show', 'report', 'stix', 'handoff',
]);

const DOMAIN_TOOL = {
  name: 'para11ax_domain_investigation',
  title: 'PARA11AX Domain Investigation',
  description: 'Build and advance a passive suspicious-domain investigation with explicit client-carried state, bounded operator-context imports, report, STIX, and handoff projections.',
  inputSchema: Object.freeze({
    type: 'object',
    properties: Object.freeze({
      action: Object.freeze({ type: 'string', description: 'Domain Investigation action.', enum: DOMAIN_ACTIONS }),
      artifact: Object.freeze({ type: 'object', description: 'Existing Domain Investigation v1 artifact for stateful actions.', additionalProperties: true }),
      enrichment: Object.freeze({ type: 'object', description: 'Canonical Evidence v2 domain enrichment for build.', additionalProperties: true }),
      records: Object.freeze({ type: 'array', description: 'Bounded authorized operator-context records for an import action.', items: Object.freeze({ type: 'object', additionalProperties: true }) }),
    }),
    required: Object.freeze(['action']),
    additionalProperties: false,
  }),
  annotations: { readOnlyHint: false },
};

export const MCP_TOOLS = Object.freeze([...RUNTIME_MCP_TOOLS, DOMAIN_TOOL]);

function parsedBody(request) {
  const value = request?.body;
  if (typeof value === 'string') {
    try { return JSON.parse(value); }
    catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function bodyBytes(request) {
  try {
    if (typeof request?.body === 'string') return Buffer.byteLength(request.body, 'utf8');
    return Buffer.byteLength(JSON.stringify(request?.body ?? null), 'utf8');
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function requestToolName(request) {
  const body = parsedBody(request);
  return body?.method === 'tools/call' ? body.params?.name ?? null : null;
}

function domainArguments(request) {
  const body = parsedBody(request);
  if (body?.method !== 'tools/call' || body.params?.name !== DOMAIN_TOOL.name) return null;
  const args = body.params?.arguments;
  return args && typeof args === 'object' && !Array.isArray(args) ? args : null;
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function domainResponse(status, body, template = null) {
  return {
    status,
    headers: template?.headers ?? {
      ...securityHeaders(),
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
    },
    body,
  };
}

function safeMessage(error) {
  const message = typeof error?.message === 'string' ? error.message : 'operation failed';
  return message.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 500) || 'operation failed';
}

function toolSuccess(value) {
  const structuredContent = value && typeof value === 'object' && !Array.isArray(value) ? value : { value };
  return {
    content: [{ type: 'text', text: JSON.stringify(structuredContent, null, 2) }],
    structuredContent,
    isError: false,
  };
}

function toolFailure(error) {
  const message = safeMessage(error);
  return {
    content: [{ type: 'text', text: message }],
    structuredContent: { error: message },
    isError: true,
  };
}

async function runDomainInvestigation(args) {
  const map = {
    build: 'domain-investigation-build',
    surface_import: 'domain-investigation-surface-import',
    vulnerability_import: 'domain-investigation-vulnerability-import',
    show: 'domain-investigation-show',
    report: 'domain-investigation-report',
    stix: 'domain-investigation-stix',
    handoff: 'domain-investigation-handoff',
  };
  const handler = map[args.action];
  if (!handler) throw new Error('unsupported Domain Investigation action');
  if (args.action === 'build') {
    if (!args.enrichment || typeof args.enrichment !== 'object' || Array.isArray(args.enrichment)) {
      throw new Error('Evidence v2 enrichment required for Domain Investigation build');
    }
  } else if (!args.artifact || typeof args.artifact !== 'object' || Array.isArray(args.artifact)) {
    throw new Error('Domain Investigation artifact required; build first');
  }
  if (args.action === 'surface_import' || args.action === 'vulnerability_import') {
    if (!Array.isArray(args.records)) throw new Error('Domain Investigation import records required');
  }

  const content = args.action === 'build'
    ? JSON.stringify(args.enrichment)
    : (args.action === 'surface_import' || args.action === 'vulnerability_import' ? JSON.stringify(args.records) : null);
  const outcome = await executeDomainInvestigationCommand({
    handler,
    args: [],
    artifact: args.artifact ?? null,
    loadContent: content === null ? null : async () => content,
  });

  if (args.action === 'build' || args.action === 'surface_import' || args.action === 'vulnerability_import') {
    return { artifact: outcome.artifact, result: outcome.output.value };
  }
  if (args.action === 'show') return { result: outcome.output.value };
  if (args.action === 'report') return { report: outcome.output.value };
  if (args.action === 'stix') return { bundle: outcome.output.value };
  if (args.action === 'handoff') return { handoff: outcome.output.value };
  throw new Error('unsupported Domain Investigation action');
}

function largeDomainTransition(args) {
  if (!args || !DOMAIN_ACTIONS.includes(args.action)) return false;
  if (args.action === 'build') return Boolean(args.enrichment && typeof args.enrichment === 'object' && !Array.isArray(args.enrichment));
  if (args.action === 'surface_import' || args.action === 'vulnerability_import') {
    return Boolean(args.artifact && typeof args.artifact === 'object' && !Array.isArray(args.artifact) && Array.isArray(args.records));
  }
  return false;
}

function validationProbe(request, body) {
  const headers = { ...(request?.headers ?? {}) };
  delete headers['content-length'];
  delete headers['Content-Length'];
  return {
    ...request,
    headers,
    body: {
      jsonrpc: '2.0',
      id: body?.id ?? null,
      method: 'tools/call',
      params: { name: DOMAIN_TOOL.name, arguments: { action: 'show', artifact: {} } },
    },
  };
}

function appendDomainTool(response) {
  const tools = response?.body?.result?.tools;
  if (!Array.isArray(tools) || tools.some(tool => tool?.name === DOMAIN_TOOL.name)) return response;
  return {
    ...response,
    body: {
      ...response.body,
      result: { ...response.body.result, tools: [...tools, DOMAIN_TOOL] },
    },
  };
}

function appendDomainCapability(response) {
  const structured = response?.body?.result?.structuredContent;
  if (!structured || !Array.isArray(structured.tools) || structured.tools.some(tool => tool?.name === DOMAIN_TOOL.name)) return response;
  const summary = { name: DOMAIN_TOOL.name, title: DOMAIN_TOOL.title, description: DOMAIN_TOOL.description };
  const enriched = { ...structured, tools: [...structured.tools, summary] };
  return {
    ...response,
    body: {
      ...response.body,
      result: {
        ...response.body.result,
        structuredContent: enriched,
        content: [{ type: 'text', text: JSON.stringify(enriched, null, 2) }],
      },
    },
  };
}

function withMissionExecutionPlan(response) {
  if (!response || response.status !== 200) return response;
  const result = response.body?.result;
  const structuredContent = result?.structuredContent;
  if (!result || result.isError === true || !structuredContent?.workspace) return response;

  const enriched = {
    ...structuredContent,
    executionPlan: buildAgentExecutionPlan(structuredContent.workspace),
  };

  return {
    ...response,
    body: {
      ...response.body,
      result: {
        ...result,
        structuredContent: enriched,
        content: [{ type: 'text', text: JSON.stringify(enriched, null, 2) }],
      },
    },
  };
}

export function createMcpHttpHandler(options = {}) {
  const runtime = createRuntimeMcpHttpHandler(options);
  const env = options.env ?? process.env;
  const nowMs = options.nowMs ?? (() => Date.now());

  return async function handleMcp(request) {
    const body = parsedBody(request);
    const args = domainArguments(request);
    const bytes = bodyBytes(request);

    if (args) {
      const authorization = verifyMcpAuthorization(request, env.PARA11AX_TOKEN, nowMs());
      if (bytes > MAX_BODY_BYTES) {
        const allowed = authorization.authorized && bytes <= MAX_LARGE_BODY_BYTES && largeDomainTransition(args);
        if (!allowed) return domainResponse(413, rpcError(body?.id, -32700, 'Payload too large'));
      }

      const validation = await runtime(bytes > MAX_BODY_BYTES ? validationProbe(request, body) : request);
      if (!authorization.authorized || validation.status !== 200 || validation.body?.error) return validation;

      try {
        const value = await runDomainInvestigation(args);
        return domainResponse(200, { jsonrpc: '2.0', id: body?.id ?? null, result: toolSuccess(value) }, validation);
      } catch (error) {
        return domainResponse(200, { jsonrpc: '2.0', id: body?.id ?? null, result: toolFailure(error) }, validation);
      }
    }

    let response = await runtime(request);
    if (body?.method === 'tools/list') response = appendDomainTool(response);
    if (requestToolName(request) === 'para11ax_capabilities') response = appendDomainCapability(response);
    if (requestToolName(request) === 'para11ax_mission') response = withMissionExecutionPlan(response);
    return response;
  };
}

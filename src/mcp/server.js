import { buildAgentExecutionPlan } from '../core/agent-execution-plan.js';
import { createMcpHttpHandler as createRuntimeMcpHttpHandler } from './server-runtime.js';

export { MCP_PROTOCOL_VERSION, MCP_TOOLS } from './server-runtime.js';

function requestToolName(request) {
  let body = request?.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); }
    catch { return null; }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  return body.method === 'tools/call' ? body.params?.name ?? null : null;
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
  return async function handleMcp(request) {
    const response = await runtime(request);
    if (requestToolName(request) !== 'para11ax_mission') return response;
    return withMissionExecutionPlan(response);
  };
}

import { createMcpHttpHandler } from '../src/mcp/transport.js';
import { createMcpOAuthHandlers } from '../src/mcp/oauth.js';

const handleMcp = createMcpHttpHandler();
const oauth = createMcpOAuthHandlers();

function requestedRoute(req) {
  const value = req?.query?._para11ax_mcp_route;
  if (Array.isArray(value)) return value.length === 1 ? value[0] : '';
  return typeof value === 'string' ? value : '';
}

export default async function handler(req, res) {
  const route = requestedRoute(req);
  const result = route === 'protected-resource'
    ? oauth.handleProtectedResource(req)
    : route === 'authorization-metadata'
      ? oauth.handleAuthorizationMetadata(req)
      : route === 'authorize'
        ? oauth.handleAuthorize(req)
        : route === 'token'
          ? oauth.handleToken(req)
          : await handleMcp(req);
  res.status(result.status);
  for (const [name, value] of Object.entries(result.headers ?? {})) res.setHeader(name, value);
  if (result.body === null || result.body === undefined) {
    res.end();
    return;
  }
  const contentType = String(result.headers?.['content-type'] ?? '').toLowerCase();
  res.end(contentType.startsWith('text/html') && typeof result.body === 'string'
    ? result.body
    : JSON.stringify(result.body));
}

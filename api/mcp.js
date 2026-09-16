import { createMcpHttpHandler } from '../src/mcp/transport.js';
import { createMcpOAuthHandlers } from '../src/mcp/oauth.js';
import { normalizeExternalMcpResponse } from '../src/mcp/external-auth-recovery.js';
import { requestUrl, singleRequestQueryValue } from '../src/core/http.js';

const handleMcp = createMcpHttpHandler();
const oauth = createMcpOAuthHandlers();

function requestedRoute(req) {
  const internal = singleRequestQueryValue(req, '_para11ax_mcp_route');
  if (internal) return internal;
  const pathname = requestUrl(req)?.pathname;
  if (pathname === '/.well-known/oauth-protected-resource' || pathname === '/.well-known/oauth-protected-resource/mcp') return 'protected-resource';
  if (pathname === '/.well-known/oauth-authorization-server') return 'authorization-metadata';
  if (pathname === '/oauth/authorize') return 'authorize';
  if (pathname === '/oauth/token') return 'token';
  return '';
}

export default async function handler(req, res) {
  const route = requestedRoute(req);
  const internalResult = route === 'protected-resource'
    ? oauth.handleProtectedResource(req)
    : route === 'authorization-metadata'
      ? oauth.handleAuthorizationMetadata(req)
      : route === 'authorize'
        ? oauth.handleAuthorize(req)
        : route === 'token'
          ? oauth.handleToken(req)
          : await handleMcp(req);
  const result = normalizeExternalMcpResponse(route, internalResult);
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

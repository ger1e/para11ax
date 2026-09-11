import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

import { requireGatewayAuth } from '../core/auth.js';
import { securityHeaders } from '../core/http.js';

export const MCP_RESOURCE = 'https://para11ax.vercel.app/mcp';
export const MCP_AUTH_ISSUER = 'https://para11ax.vercel.app';
export const MCP_OAUTH_SCOPE = 'para11ax:use';
export const MCP_OFFLINE_SCOPE = 'offline_access';
export const MCP_PROTECTED_RESOURCE_METADATA = `${MCP_AUTH_ISSUER}/.well-known/oauth-protected-resource`;

const AUTHORIZATION_ENDPOINT = `${MCP_AUTH_ISSUER}/oauth/authorize`;
const TOKEN_ENDPOINT = `${MCP_AUTH_ISSUER}/oauth/token`;
const CHATGPT_CLIENT_ID = 'https://chatgpt.com/oauth/client.json';
const CHATGPT_REDIRECT_URI = 'https://chatgpt.com/connector_platform_oauth_redirect';
const CODE_TTL_SECONDS = 180;
const ACCESS_TTL_SECONDS = 30 * 24 * 60 * 60;
const REFRESH_TTL_SECONDS = 180 * 24 * 60 * 60;
const MAX_FORM_BYTES = 16 * 1024;
const PKCE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const AUTHORIZATION_SCOPES = new Set([MCP_OAUTH_SCOPE, MCP_OFFLINE_SCOPE]);

function response(status, body, extraHeaders = {}) {
  return {
    status,
    headers: {
      ...securityHeaders(),
      'cache-control': 'no-store',
      ...extraHeaders,
    },
    body,
  };
}

function oauthJson(status, body, extraHeaders = {}) {
  return response(status, body, {
    pragma: 'no-cache',
    'content-type': 'application/json; charset=utf-8',
    ...extraHeaders,
  });
}

function methodNotAllowed(allow) {
  return oauthJson(405, { error: 'method_not_allowed' }, { allow });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
}

function scalar(value) {
  if (Array.isArray(value)) return value.length === 1 ? String(value[0]) : null;
  if (value === undefined || value === null) return null;
  return String(value);
}

function normalizeScope(value) {
  if (typeof value !== 'string') return null;
  const requested = [...new Set(value.trim().split(/\s+/).filter(Boolean))];
  if (!requested.includes(MCP_OAUTH_SCOPE) || requested.some(scope => !AUTHORIZATION_SCOPES.has(scope))) return null;
  return [MCP_OAUTH_SCOPE, ...(requested.includes(MCP_OFFLINE_SCOPE) ? [MCP_OFFLINE_SCOPE] : [])].join(' ');
}

function hasScope(scopeValue, required) {
  return typeof scopeValue === 'string' && scopeValue.split(/\s+/).includes(required);
}

function queryValues(request) {
  if (request?.query && typeof request.query === 'object') return request.query;
  try {
    return Object.fromEntries(new URL(request?.url ?? '', MCP_AUTH_ISSUER).searchParams.entries());
  } catch {
    return {};
  }
}

function parseFormBody(request) {
  const declared = Number(headerValue(request?.headers, 'content-length'));
  if (Number.isFinite(declared) && declared > MAX_FORM_BYTES) throw new Error('form_too_large');
  const body = request?.body;
  if (body && typeof body === 'object' && !Array.isArray(body) && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : typeof body === 'string' ? body : '';
  if (Buffer.byteLength(text, 'utf8') > MAX_FORM_BYTES) throw new Error('form_too_large');
  return Object.fromEntries(new URLSearchParams(text).entries());
}

function authorizeValues(source) {
  return {
    responseType: scalar(source.response_type),
    clientId: scalar(source.client_id),
    redirectUri: scalar(source.redirect_uri),
    resource: scalar(source.resource),
    scope: normalizeScope(scalar(source.scope)),
    state: scalar(source.state),
    codeChallenge: scalar(source.code_challenge),
    codeChallengeMethod: scalar(source.code_challenge_method),
  };
}

function validAuthorizeValues(value) {
  return value.responseType === 'code'
    && value.clientId === CHATGPT_CLIENT_ID
    && value.redirectUri === CHATGPT_REDIRECT_URI
    && value.resource === MCP_RESOURCE
    && typeof value.scope === 'string'
    && value.scope.length > 0
    && typeof value.state === 'string'
    && value.state.length >= 1
    && value.state.length <= 2048
    && typeof value.codeChallenge === 'string'
    && PKCE_CHALLENGE.test(value.codeChallenge)
    && value.codeChallengeMethod === 'S256';
}

function encode(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function signingKey(secret) {
  return scryptSync(secret, 'para11ax:mcp-oauth:signing-key:v1', 32);
}

function sign(payload, secret) {
  const header = encode({ alg: 'HS256', kid: 'para11ax-mcp-oauth-v1', typ: 'JWT' });
  const encodedPayload = encode(payload);
  const value = `${header}.${encodedPayload}`;
  const signature = createHmac('sha256', signingKey(secret)).update(value, 'utf8').digest('base64url');
  return `${value}.${signature}`;
}

function verifySignature(token, secret) {
  if (typeof token !== 'string' || token.length < 32 || token.length > 8192) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(part => !part)) return null;
  const value = `${parts[0]}.${parts[1]}`;
  const expected = createHmac('sha256', signingKey(secret)).update(value, 'utf8').digest();
  let supplied;
  try { supplied = Buffer.from(parts[2], 'base64url'); } catch { return null; }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!header || header.alg !== 'HS256' || header.kid !== 'para11ax-mcp-oauth-v1' || header.typ !== 'JWT') return null;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    return payload;
  } catch {
    return null;
  }
}

function validTimes(payload, nowSeconds, maxLifetime) {
  return Number.isSafeInteger(payload.iat)
    && Number.isSafeInteger(payload.exp)
    && payload.iat <= nowSeconds + 30
    && payload.exp > nowSeconds
    && payload.exp - payload.iat > 0
    && payload.exp - payload.iat <= maxLifetime;
}

function issueAuthorizationCode(value, secret, nowSeconds) {
  return sign({
    v: 1,
    typ: 'authorization_code',
    iss: MCP_AUTH_ISSUER,
    aud: TOKEN_ENDPOINT,
    iat: nowSeconds,
    exp: nowSeconds + CODE_TTL_SECONDS,
    jti: randomBytes(18).toString('base64url'),
    client_id: value.clientId,
    redirect_uri: value.redirectUri,
    resource: value.resource,
    scope: value.scope,
    code_challenge: value.codeChallenge,
  }, secret);
}

function readAuthorizationCode(code, secret, nowSeconds) {
  const payload = verifySignature(code, secret);
  if (!payload
    || payload.v !== 1
    || payload.typ !== 'authorization_code'
    || payload.iss !== MCP_AUTH_ISSUER
    || payload.aud !== TOKEN_ENDPOINT
    || payload.client_id !== CHATGPT_CLIENT_ID
    || payload.redirect_uri !== CHATGPT_REDIRECT_URI
    || payload.resource !== MCP_RESOURCE
    || normalizeScope(payload.scope) !== payload.scope
    || typeof payload.jti !== 'string'
    || !PKCE_CHALLENGE.test(String(payload.code_challenge ?? ''))
    || !validTimes(payload, nowSeconds, CODE_TTL_SECONDS)) return null;
  return payload;
}

function issueAccessToken(secret, nowSeconds, scope = MCP_OAUTH_SCOPE) {
  return sign({
    v: 1,
    typ: 'access_token',
    iss: MCP_AUTH_ISSUER,
    aud: MCP_RESOURCE,
    sub: 'para11ax-owner',
    iat: nowSeconds,
    nbf: nowSeconds - 5,
    exp: nowSeconds + ACCESS_TTL_SECONDS,
    jti: randomBytes(18).toString('base64url'),
    client_id: CHATGPT_CLIENT_ID,
    scope,
  }, secret);
}

function readAccessToken(token, secret, nowSeconds) {
  const payload = verifySignature(token, secret);
  if (!payload
    || payload.v !== 1
    || payload.typ !== 'access_token'
    || payload.iss !== MCP_AUTH_ISSUER
    || payload.aud !== MCP_RESOURCE
    || payload.sub !== 'para11ax-owner'
    || payload.client_id !== CHATGPT_CLIENT_ID
    || !hasScope(payload.scope, MCP_OAUTH_SCOPE)
    || typeof payload.jti !== 'string'
    || !Number.isSafeInteger(payload.nbf)
    || payload.nbf > nowSeconds
    || !validTimes(payload, nowSeconds, ACCESS_TTL_SECONDS)) return null;
  return payload;
}

function issueRefreshToken(secret, nowSeconds, scope) {
  return sign({
    v: 1,
    typ: 'refresh_token',
    iss: MCP_AUTH_ISSUER,
    aud: TOKEN_ENDPOINT,
    sub: 'para11ax-owner',
    iat: nowSeconds,
    exp: nowSeconds + REFRESH_TTL_SECONDS,
    jti: randomBytes(18).toString('base64url'),
    client_id: CHATGPT_CLIENT_ID,
    resource: MCP_RESOURCE,
    scope,
  }, secret);
}

function readRefreshToken(token, secret, nowSeconds) {
  const payload = verifySignature(token, secret);
  if (!payload
    || payload.v !== 1
    || payload.typ !== 'refresh_token'
    || payload.iss !== MCP_AUTH_ISSUER
    || payload.aud !== TOKEN_ENDPOINT
    || payload.sub !== 'para11ax-owner'
    || payload.client_id !== CHATGPT_CLIENT_ID
    || payload.resource !== MCP_RESOURCE
    || normalizeScope(payload.scope) !== payload.scope
    || !hasScope(payload.scope, MCP_OFFLINE_SCOPE)
    || typeof payload.jti !== 'string'
    || !validTimes(payload, nowSeconds, REFRESH_TTL_SECONDS)) return null;
  return payload;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function hidden(name, value) {
  return `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`;
}

function authorizationPage(value, error = '') {
  const fields = [
    ['response_type', value.responseType],
    ['client_id', value.clientId],
    ['redirect_uri', value.redirectUri],
    ['resource', value.resource],
    ['scope', value.scope],
    ['state', value.state],
    ['code_challenge', value.codeChallenge],
    ['code_challenge_method', value.codeChallengeMethod],
  ].map(([name, fieldValue]) => hidden(name, fieldValue)).join('\n');
  const errorMarkup = error ? `<p role="alert" class="error">${escapeHtml(error)}</p>` : '';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Authorize ChatGPT — PARA11AX</title>
  <style>
    :root{color-scheme:dark}body{background:#050806;color:#b7ffbf;font:16px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;margin:0;padding:32px}main{max-width:620px;margin:8vh auto;border:1px solid #29d55d;padding:28px;box-shadow:0 0 28px #29d55d22}h1{font-size:24px;letter-spacing:.08em;margin-top:0}label{display:block;margin:24px 0 8px}input[type=password]{box-sizing:border-box;width:100%;padding:12px;background:#0b120d;color:#eaffed;border:1px solid #51845d;font:inherit}button{margin-top:18px;padding:11px 18px;background:#29d55d;color:#031006;border:0;font:inherit;font-weight:700;cursor:pointer}.error{color:#ff8d8d}.scope{color:#a7b7aa;font-size:14px}</style>
</head>
<body><main>
  <h1>PΛRΛ11ΛX</h1>
  <p>Authorize ChatGPT to use the complete PARA11AX MCP toolset.</p>
  <p class="scope">Scope: enrichment, providers, User Scanner, Shodan, GreyNoise Swarm, STIX, missions, investigations, cases, reports, and registered safe commands.</p>
  ${errorMarkup}
  <form method="post" action="/oauth/authorize">
    ${fields}
    <label for="gateway_token">PARA11AX gateway access token</label>
    <input id="gateway_token" name="gateway_token" type="password" required autocomplete="current-password" spellcheck="false">
    <button type="submit">Authorize ChatGPT</button>
  </form>
</main></body>
</html>`;
}

function htmlResponse(status, body) {
  return response(status, body, {
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy': `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${CHATGPT_REDIRECT_URI}; frame-ancestors 'none'; base-uri 'none'`,
  });
}

function tokenError(status, error, description) {
  return oauthJson(status, { error, error_description: description });
}

function validGatewayCredential(candidate, secret) {
  if (typeof candidate !== 'string' || typeof secret !== 'string' || !secret) return false;
  return requireGatewayAuth({ headers: { authorization: `Bearer ${candidate}` } }, secret);
}

function safePkceMatch(verifier, challenge) {
  if (!PKCE_VERIFIER.test(verifier)) return false;
  const actual = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  const expected = Buffer.from(challenge, 'ascii');
  const supplied = Buffer.from(actual, 'ascii');
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

export function mcpWwwAuthenticate(error = 'invalid_token', description = 'Link PARA11AX to continue') {
  return `Bearer resource_metadata="${MCP_PROTECTED_RESOURCE_METADATA}", scope="${MCP_OAUTH_SCOPE}", error="${error}", error_description="${description}"`;
}

export function verifyMcpAuthorization(request, secret, nowMs = Date.now()) {
  if (typeof secret !== 'string' || secret.length === 0) return { authorized: false, scheme: null };
  if (requireGatewayAuth(request, secret)) return { authorized: true, scheme: 'gateway_bearer' };
  const authorization = String(headerValue(request?.headers, 'authorization') ?? '');
  if (!authorization.startsWith('Bearer ')) return { authorized: false, scheme: null };
  const token = authorization.slice(7).trim();
  const claims = readAccessToken(token, secret, Math.floor(nowMs / 1000));
  return claims ? { authorized: true, scheme: 'oauth2', claims } : { authorized: false, scheme: null };
}

export function createMcpOAuthHandlers({ env = process.env, nowMs = () => Date.now() } = {}) {
  const consumedCodes = new Map();

  function configured() {
    return typeof env.PARA11AX_TOKEN === 'string' && env.PARA11AX_TOKEN.length > 0;
  }

  function consumeAuthorizationCode(claims, nowSeconds) {
    for (const [id, expiresAt] of consumedCodes) {
      if (expiresAt <= nowSeconds) consumedCodes.delete(id);
    }
    if (consumedCodes.has(claims.jti)) return false;
    while (consumedCodes.size >= 1024) consumedCodes.delete(consumedCodes.keys().next().value);
    consumedCodes.set(claims.jti, claims.exp);
    return true;
  }

  function tokenSuccess(scope, nowSeconds, { includeRefresh = false } = {}) {
    return oauthJson(200, {
      access_token: issueAccessToken(env.PARA11AX_TOKEN, nowSeconds, scope),
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_SECONDS,
      scope,
      ...(includeRefresh ? { refresh_token: issueRefreshToken(env.PARA11AX_TOKEN, nowSeconds, scope) } : {}),
    });
  }

  return {
    handleProtectedResource(request) {
      if (request?.method !== 'GET') return methodNotAllowed('GET');
      return oauthJson(200, {
        resource: MCP_RESOURCE,
        authorization_servers: [MCP_AUTH_ISSUER],
        scopes_supported: [MCP_OAUTH_SCOPE],
        resource_documentation: 'https://github.com/ger1e/para11ax/blob/main/docs/MCP.md',
      });
    },

    handleAuthorizationMetadata(request) {
      if (request?.method !== 'GET') return methodNotAllowed('GET');
      return oauthJson(200, {
        issuer: MCP_AUTH_ISSUER,
        authorization_endpoint: AUTHORIZATION_ENDPOINT,
        token_endpoint: TOKEN_ENDPOINT,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['none'],
        client_id_metadata_document_supported: true,
        authorization_response_iss_parameter_supported: true,
        scopes_supported: [MCP_OAUTH_SCOPE, MCP_OFFLINE_SCOPE],
        resource_parameter_supported: true,
      });
    },

    handleAuthorize(request) {
      if (!['GET', 'POST'].includes(request?.method)) return methodNotAllowed('GET, POST');
      if (!configured()) return htmlResponse(503, '<!doctype html><title>PARA11AX unavailable</title><p>Authorization is not configured.</p>');
      let source;
      try { source = request.method === 'POST' ? parseFormBody(request) : queryValues(request); }
      catch { return htmlResponse(413, '<!doctype html><title>Invalid request</title><p>Authorization request is too large.</p>'); }
      const value = authorizeValues(source);
      if (!validAuthorizeValues(value)) return htmlResponse(400, '<!doctype html><title>Invalid request</title><p>The OAuth authorization request is invalid.</p>');
      if (request.method === 'GET') return htmlResponse(200, authorizationPage(value));

      const candidate = scalar(source.gateway_token);
      if (!validGatewayCredential(candidate, env.PARA11AX_TOKEN)) {
        return htmlResponse(401, authorizationPage(value, 'The gateway access token was not accepted.'));
      }

      const code = issueAuthorizationCode(value, env.PARA11AX_TOKEN, Math.floor(nowMs() / 1000));
      const redirect = new URL(value.redirectUri);
      redirect.searchParams.set('code', code);
      redirect.searchParams.set('state', value.state);
      redirect.searchParams.set('iss', MCP_AUTH_ISSUER);
      return response(302, null, { location: redirect.toString(), 'content-type': 'text/plain; charset=utf-8' });
    },

    handleToken(request) {
      if (request?.method !== 'POST') return methodNotAllowed('POST');
      if (!configured()) return tokenError(503, 'temporarily_unavailable', 'Authorization is not configured');
      const contentType = String(headerValue(request.headers, 'content-type') ?? '').split(';', 1)[0].trim().toLowerCase();
      if (contentType !== 'application/x-www-form-urlencoded') return tokenError(415, 'invalid_request', 'Form encoding is required');
      let source;
      try { source = parseFormBody(request); }
      catch { return tokenError(413, 'invalid_request', 'Request is too large'); }

      const grantType = scalar(source.grant_type);
      const clientId = scalar(source.client_id);
      const resource = scalar(source.resource);
      if (clientId !== CHATGPT_CLIENT_ID) return tokenError(401, 'invalid_client', 'Unknown OAuth client');
      if (resource !== null && resource !== MCP_RESOURCE) return tokenError(400, 'invalid_grant', 'Authorization binding does not match');

      const nowSeconds = Math.floor(nowMs() / 1000);

      if (grantType === 'refresh_token') {
        const refreshToken = scalar(source.refresh_token);
        if (!refreshToken) return tokenError(400, 'invalid_request', 'Refresh token is required');
        const claims = readRefreshToken(refreshToken, env.PARA11AX_TOKEN, nowSeconds);
        if (!claims || claims.client_id !== clientId || claims.resource !== MCP_RESOURCE) {
          return tokenError(400, 'invalid_grant', 'Refresh token is invalid or expired');
        }
        const requestedScope = scalar(source.scope);
        if (requestedScope !== null && normalizeScope(requestedScope) !== claims.scope) {
          return tokenError(400, 'invalid_scope', 'Refresh scope cannot expand or alter the original grant');
        }
        return tokenSuccess(claims.scope, nowSeconds, { includeRefresh: true });
      }

      const code = scalar(source.code);
      const redirectUri = scalar(source.redirect_uri);
      const verifier = scalar(source.code_verifier);
      if (grantType !== 'authorization_code' || !code || !verifier) return tokenError(400, 'invalid_request', 'Authorization code and PKCE verifier are required');
      if (redirectUri !== CHATGPT_REDIRECT_URI || resource !== MCP_RESOURCE) return tokenError(400, 'invalid_grant', 'Authorization binding does not match');

      const claims = readAuthorizationCode(code, env.PARA11AX_TOKEN, nowSeconds);
      if (!claims
        || claims.client_id !== clientId
        || claims.redirect_uri !== redirectUri
        || claims.resource !== resource
        || !safePkceMatch(verifier, claims.code_challenge)) {
        return tokenError(400, 'invalid_grant', 'Authorization code or PKCE verifier is invalid');
      }
      if (!consumeAuthorizationCode(claims, nowSeconds)) return tokenError(400, 'invalid_grant', 'Authorization code was already used');

      return tokenSuccess(claims.scope, nowSeconds, { includeRefresh: hasScope(claims.scope, MCP_OFFLINE_SCOPE) });
    },
  };
}
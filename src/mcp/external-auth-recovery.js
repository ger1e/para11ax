const MAX_CHALLENGE_BYTES = 2048;

function safeChallenge(value) {
  if (typeof value !== 'string' || !value.startsWith('Bearer ')) return null;
  if (/\r|\n/.test(value) || Buffer.byteLength(value, 'utf8') > MAX_CHALLENGE_BYTES) return null;
  return value;
}

function authChallenge(result) {
  const values = result?.body?.result?._meta?.['mcp/www_authenticate'];
  if (!Array.isArray(values) || values.length < 1) return null;
  return safeChallenge(values[0]);
}

function isAuthenticationRequired(result) {
  return result?.status === 200
    && result?.body?.result?.isError === true
    && result?.body?.result?.structuredContent?.error === 'authentication_required';
}

export function normalizeExternalMcpResponse(route, result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) return result;
  if (route !== '' || !isAuthenticationRequired(result)) return result;

  const challenge = authChallenge(result);
  if (!challenge) return result;

  return {
    status: 401,
    headers: {
      ...(result.headers ?? {}),
      'www-authenticate': challenge,
    },
    body: { error: 'unauthorized' },
  };
}

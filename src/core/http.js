export function securityHeaders() {
  return {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'referrer-policy': 'no-referrer',
  };
}

export function requestUrl(request, base = 'https://para11ax.invalid') {
  if (typeof request?.url !== 'string' || !request.url) return null;
  try {
    return new URL(request.url, base);
  } catch {
    return null;
  }
}

export function requestQueryValues(request, base) {
  const parsed = requestUrl(request, base);
  if (!parsed) return {};
  const values = Object.create(null);
  for (const [name, value] of parsed.searchParams) {
    const existing = values[name];
    if (existing === undefined) values[name] = value;
    else if (Array.isArray(existing)) existing.push(value);
    else values[name] = [existing, value];
  }
  return values;
}

export function singleRequestQueryValue(request, name, base) {
  const value = requestQueryValues(request, base)[name];
  if (Array.isArray(value)) return value.length === 1 ? value[0] : null;
  return typeof value === 'string' ? value : null;
}

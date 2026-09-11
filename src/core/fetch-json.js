function httpError(response) {
  const error = new Error(`provider HTTP ${response.status}`);
  error.status = response.status;
  error.retryAfter = response.headers.get('retry-after');
  return error;
}

function mergeHeaders(defaults = {}, overrides = {}) {
  const output = {};
  const index = new Map();
  const set = (key, value) => {
    const normalized = String(key).toLowerCase();
    const existing = index.get(normalized);
    if (existing !== undefined) delete output[existing];
    output[key] = value;
    index.set(normalized, key);
  };
  for (const [key, value] of Object.entries(defaults)) set(key, value);
  for (const [key, value] of Object.entries(overrides)) set(key, value);
  return output;
}

export async function fetchJson(url, {
  fetchImpl = fetch,
  signal,
  maxBytes = 2_000_000,
  method = 'GET',
  headers = {},
  body,
  redirect = 'error',
} = {}) {
  const requestHeaders = mergeHeaders({ accept: 'application/json' }, headers);
  const response = await fetchImpl(url, {
    method,
    signal,
    headers: requestHeaders,
    body,
    redirect,
  });
  if (!response.ok) throw httpError(response);
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) throw Object.assign(new Error('provider response too large'), { status: 502 });
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw Object.assign(new Error('provider response too large'), { status: 502 });
  if (!text) return null;
  return JSON.parse(text);
}

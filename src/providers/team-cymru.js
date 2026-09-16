const API_URL = 'https://v4.whois.cymru.com/cgi-bin/whois.cgi';
const SOURCE_URL = 'https://www.team-cymru.com/ip-asn-mapping';
const MAX_RESPONSE_BYTES = 1024 * 1024;

function validIpv4(value) {
  if (typeof value !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return false;
  return value.split('.').every(part => Number(part) >= 0 && Number(part) <= 255);
}

function extractPre(value) {
  const match = /<pre[^>]*>([\s\S]*?)<\/pre>/i.exec(value);
  const content = match?.[1] ?? value;
  if (/<[^>]+>/.test(content)) throw new Error('provider_schema_invalid');
  return content.trim();
}

function noResult() {
  return {
    observationType: 'network_identity',
    verdict: 'no_result',
    confidence: null,
    attributes: {},
    relationships: [],
    references: [SOURCE_URL],
  };
}

async function fetchText(body, { fetchImpl, signal }) {
  const response = await fetchImpl(API_URL, {
    method: 'POST',
    signal,
    redirect: 'error',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'text/html' },
    body,
  });
  if (!response.ok) {
    const error = new Error(`provider HTTP ${response.status}`);
    error.status = response.status;
    error.retryAfter = response.headers.get('retry-after');
    throw error;
  }
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw Object.assign(new Error('provider response too large'), { status: 502 });
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw Object.assign(new Error('provider response too large'), { status: 502 });
  return text;
}

export const teamCymruProvider = Object.freeze({
  name: 'team-cymru',
  types: ['ip'],
  observationType: 'network_identity',
  cacheTtlMs: 24 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'free',
  timeoutMs: 5000,
  parserVersion: 'team-cymru-whois-2026-09-16.1',
  async run(input, { signal, fetchImpl = fetch } = {}) {
    if (input?.type !== 'ip' || !validIpv4(input.value)) throw new Error('unsupported Team Cymru input');
    const form = new URLSearchParams({
      action: 'do_whois',
      family: 'ipv4',
      method_whois: 'whois',
      bulk_paste: input.value,
    });
    const raw = await fetchText(form.toString(), { fetchImpl, signal });
    const lines = extractPre(raw).split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    if (lines.length < 2) throw new Error('provider_schema_invalid');
    const row = lines.slice(1).find(line => line.includes('|'));
    if (!row) return noResult();
    const parts = row.split('|').map(part => part.trim());
    if (parts.length < 3) throw new Error('provider_schema_invalid');
    const [asnRaw, , prefix = '', countryCode = '', registry = '', allocated = '', ...nameParts] = parts;
    if (!asnRaw || asnRaw.toUpperCase() === 'NA') return noResult();
    if (!/^\d+$/.test(asnRaw)) throw new Error('provider_schema_invalid');
    const asName = nameParts.join(' | ').trim();
    return {
      observationType: 'network_identity',
      verdict: 'observed',
      confidence: null,
      attributes: {
        asn: `AS${asnRaw}`,
        prefix,
        countryCode,
        registry,
        allocated,
        asName,
      },
      relationships: [],
      references: [SOURCE_URL],
    };
  },
});

const PROFILES = new Set(['fast', 'standard', 'full']);
const SHODAN_COMMANDS = new Set(['host', 'search', 'count', 'stats', 'domain', 'info']);
const SWARM_COMMANDS = new Set(['search', 'get', 'export', 'unique', 'timeseries']);
const SWARM_READ_COMMANDS = new Set(['search', 'get', 'unique', 'timeseries']);
const SWARM_EXPORT_TYPES = new Set(['pcap', 'rawSource', 'rawDestination']);
const SWARM_PIVOT_FIELDS = new Set([
  'source.ip', 'destination.ip', 'source.port', 'destination.port', 'classification', 'protocol', 'ipProtocol',
  'sourceMetadata.asn', 'sourceMetadata.org', 'sourceMetadata.country_code',
  'destinationMetadata.asn', 'destinationMetadata.org', 'destinationMetadata.country_code',
  'gnTagMetadata.name', 'gnTagMetadata.slug', 'gnTagMetadata.category', 'gnTagMetadata.intention', 'gnTagMetadata.cves',
  'tls.ja3', 'tls.ja4', 'tcp.ja4t', 'suricata.signature', 'suricata.category', 'suricata.severity',
]);
const SWARM_TIMESERIES_INTERVALS = new Set(['auto', '1s', '1m', '1h', '1d']);
const PROVIDER_NAME_RE = /^[a-z0-9-]{1,64}$/;
const ENRICHMENT_OBSERVERS = new Set();
const MAX_SWARM_EXPORT_BYTES = 4 * 1024 * 1024;
let latestGatewayClient = null;

export class GatewayHttpError extends Error {
  constructor(status, code, requestId = null) {
    super(`gateway request failed: ${code || status}`);
    this.name = 'GatewayHttpError';
    this.status = status;
    this.code = code || 'request_failed';
    this.requestId = requestId;
  }
}

export function addGatewayEnrichmentObserver(observer) {
  if (typeof observer !== 'function') throw new TypeError('enrichment observer must be a function');
  ENRICHMENT_OBSERVERS.add(observer);
  return () => ENRICHMENT_OBSERVERS.delete(observer);
}

export function getLatestGatewayClient() {
  return latestGatewayClient;
}

async function notifyEnrichmentObservers(result) {
  for (const observer of [...ENRICHMENT_OBSERVERS]) {
    try {
      await observer(structuredClone(result));
    } catch {
      // Local observers must never alter or invalidate a successful gateway result.
    }
  }
}

function validEnvelope(value) {
  return Boolean(
    value &&
    typeof value === 'object' &&
    typeof value.requestId === 'string' &&
    typeof value.indicator === 'string' &&
    typeof value.type === 'string' &&
    PROFILES.has(value.profile) &&
    ['ok', 'partial', 'error'].includes(value.status) &&
    Array.isArray(value.evidence) &&
    Array.isArray(value.failures) &&
    Array.isArray(value.relationships) &&
    value.correlation &&
    typeof value.correlation === 'object'
  );
}

function validStix(value) {
  return Boolean(value && typeof value === 'object' && value.type === 'bundle' && Array.isArray(value.objects));
}

function validBatch(value) {
  return Boolean(
    value &&
    typeof value === 'object' &&
    typeof value.requestId === 'string' &&
    PROFILES.has(value.profile) &&
    Number.isInteger(value.inputCount) &&
    value.inputCount >= 1 &&
    Array.isArray(value.results)
  );
}

function validMeta(value) {
  return Boolean(value && typeof value === 'object' && typeof value.gatewayVersion === 'string' && Array.isArray(value.profiles) && value.limits && typeof value.limits === 'object');
}

function validUserScanner(value) {
  return Boolean(
    value &&
    typeof value === 'object' &&
    typeof value.scanId === 'string' &&
    ['email', 'username'].includes(value.scanType) &&
    typeof value.target === 'string' &&
    value.summary && typeof value.summary === 'object' &&
    Number.isInteger(value.summary.totalScanned) && value.summary.totalScanned >= 0 &&
    Number.isInteger(value.summary.found) && value.summary.found >= 0 &&
    Number.isInteger(value.summary.notFound) && value.summary.notFound >= 0 &&
    Number.isInteger(value.summary.errors) && value.summary.errors >= 0 &&
    Number.isInteger(value.summary.skipped) && value.summary.skipped >= 0 &&
    Array.isArray(value.results) &&
    Array.isArray(value.erroredSites) &&
    Number.isFinite(value.durationMs) && value.durationMs >= 0 &&
    value.source === 'user-scanner'
  );
}

function validShodan(value) {
  return Boolean(
    value &&
    typeof value === 'object' &&
    typeof value.requestId === 'string' &&
    value.source === 'shodan' &&
    SHODAN_COMMANDS.has(value.command) &&
    value.input && typeof value.input === 'object' && !Array.isArray(value.input) &&
    ['none', 'may_consume_query_credit', 'consumes_query_credit'].includes(value.creditImpact) &&
    value.data && typeof value.data === 'object' && !Array.isArray(value.data) &&
    Number.isFinite(value.durationMs) && value.durationMs >= 0
  );
}

function validSwarm(value) {
  return Boolean(
    value &&
    typeof value === 'object' &&
    typeof value.requestId === 'string' &&
    value.source === 'greynoise-swarm' &&
    SWARM_READ_COMMANDS.has(value.command) &&
    value.input && typeof value.input === 'object' && !Array.isArray(value.input) &&
    value.data && typeof value.data === 'object' &&
    Number.isFinite(value.durationMs) && value.durationMs >= 0
  );
}

export function createGatewayClient({ fetchImpl = fetch, getToken }) {
  if (typeof getToken !== 'function') throw new TypeError('getToken must be a function');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a function');

  async function readJsonResponse(path, response, validate) {
    const isJson = response.headers.get('content-type')?.includes('application/json');
    let payload = null;
    if (isJson) {
      try {
        payload = await response.json();
      } catch {
        throw new GatewayHttpError(502, 'unexpected_response');
      }
    }
    if (!response.ok) throw new GatewayHttpError(response.status, payload?.error, payload?.requestId);
    if (!isJson) throw new GatewayHttpError(502, 'unexpected_response');
    if (validate && !validate(payload)) {
      const code = path === '/api/para11ax/stix' ? 'invalid_stix_bundle'
        : path === '/api/para11ax/batch' ? 'invalid_batch_envelope'
          : path === '/api/para11ax/meta' ? 'invalid_meta_envelope'
            : path === '/api/para11ax/user-scanner' ? 'invalid_user_scanner_envelope'
              : path === '/api/para11ax/shodan' ? 'invalid_shodan_envelope'
                : path === '/api/para11ax/swarm' ? 'invalid_swarm_envelope'
                  : 'invalid_envelope';
      throw new GatewayHttpError(502, code);
    }
    return payload;
  }

  async function request(path, { method = 'GET', body, signal, validate } = {}) {
    if (!path.startsWith('/api/para11ax/')) throw new Error('same-origin PARA11AX API path required');
    const token = getToken();
    if (!token) throw new GatewayHttpError(401, 'unauthorized');

    const headers = { Authorization: `Bearer ${token}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetchImpl(path, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      signal,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return readJsonResponse(path, response, validate);
  }

  async function publicRequest(path, { signal, validate } = {}) {
    if (!path.startsWith('/api/para11ax/')) throw new Error('same-origin PARA11AX API path required');
    const response = await fetchImpl(path, {
      method: 'GET',
      headers: {},
      credentials: 'same-origin',
      cache: 'no-store',
      signal,
    });
    return readJsonResponse(path, response, validate);
  }

  function requestPayload(indicator, profile) {
    if (!PROFILES.has(profile)) throw new TypeError('invalid profile');
    return { indicator: String(indicator), profile };
  }

  function providerPayload(provider, indicator) {
    const name = String(provider ?? '').trim().toLowerCase();
    if (!PROVIDER_NAME_RE.test(name)) throw new TypeError('invalid provider name');
    const value = String(indicator ?? '').trim();
    if (!value) throw new TypeError('provider indicator required');
    return { provider: name, indicator: value };
  }

  function batchPayload(indicators, profile) {
    if (!PROFILES.has(profile)) throw new TypeError('invalid profile');
    if (!Array.isArray(indicators) || indicators.length < 1 || indicators.length > 20 || indicators.some(value => typeof value !== 'string')) {
      throw new TypeError('batch accepts 1..20 strings');
    }
    return { indicators: [...indicators], profile };
  }

  function userScannerPayload(input) {
    if (!input || typeof input !== 'object') throw new TypeError('user-scanner request required');
    if (!['email', 'username'].includes(input.scanType)) throw new TypeError('invalid user-scanner scan type');
    const target = String(input.target || '').trim();
    if (!target) throw new TypeError('user-scanner target required');
    if (input.category && input.module) throw new TypeError('category and module are mutually exclusive');
    const payload = {
      scanType: input.scanType,
      target,
      crossScan: Boolean(input.crossScan),
      noNsfw: input.noNsfw !== false,
    };
    if (input.category) payload.category = String(input.category);
    if (input.module) payload.module = String(input.module);
    return payload;
  }

  function shodanPayload(input) {
    if (!input || typeof input !== 'object') throw new TypeError('Shodan request required');
    const command = String(input.command || '').trim().toLowerCase();
    if (!SHODAN_COMMANDS.has(command)) throw new TypeError('invalid Shodan command');
    const payload = { command };
    if (input.target !== undefined && input.target !== null) {
      const target = String(input.target).trim();
      if (!target) throw new TypeError('invalid Shodan target');
      payload.target = target;
    }
    if (input.query !== undefined && input.query !== null) {
      const query = String(input.query).trim();
      if (!query || query.length > 1024) throw new TypeError('invalid Shodan query');
      payload.query = query;
    }
    if (input.facets !== undefined && input.facets !== null) {
      const facets = String(input.facets).trim();
      if (!facets || facets.length > 256) throw new TypeError('invalid Shodan facets');
      payload.facets = facets;
    }
    return payload;
  }

  function swarmPayload(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Swarm request required');
    const command = String(input.command || '').trim().toLowerCase();
    if (!SWARM_COMMANDS.has(command)) throw new TypeError('invalid Swarm command');
    const scope = input.scope === undefined || input.scope === null ? 'workspace' : String(input.scope).trim().toLowerCase();
    if (!['workspace', 'demo'].includes(scope)) throw new TypeError('invalid Swarm scope');
    const payload = { command, scope };

    if (command === 'search' || command === 'unique' || command === 'timeseries') {
      const startTime = String(input.startTime || '').trim();
      const endTime = String(input.endTime || '').trim();
      if (!startTime || !endTime) throw new TypeError(`Swarm ${command} time range required`);
      payload.startTime = startTime;
      payload.endTime = endTime;
      if (input.query !== undefined && input.query !== null) {
        const query = String(input.query).trim();
        if (!query || query.length > 2048 || /[\u0000-\u001f\u007f]/.test(query)) throw new TypeError('invalid Swarm query');
        payload.query = query;
      }
      if (command === 'search') {
        payload.page = Number(input.page ?? 1);
        payload.pageSize = Number(input.pageSize ?? 25);
      } else if (command === 'unique') {
        const field = String(input.field || '').trim();
        if (!SWARM_PIVOT_FIELDS.has(field)) throw new TypeError('invalid Swarm field');
        payload.field = field;
        payload.includeCounts = input.includeCounts === true;
      } else {
        if (input.field !== undefined && input.field !== null) {
          const field = String(input.field).trim();
          if (!SWARM_PIVOT_FIELDS.has(field)) throw new TypeError('invalid Swarm field');
          payload.field = field;
        }
        const size = Number(input.size ?? 10);
        if (!Number.isSafeInteger(size) || size < 1 || size > 100) throw new TypeError('invalid Swarm timeseries size');
        const interval = input.interval === undefined || input.interval === null ? 'auto' : String(input.interval).trim();
        if (!SWARM_TIMESERIES_INTERVALS.has(interval)) throw new TypeError('invalid Swarm timeseries interval');
        payload.size = size;
        payload.interval = interval;
      }
    } else {
      const sessionId = String(input.sessionId || '').trim();
      if (!sessionId) throw new TypeError('Swarm session id required');
      payload.sessionId = sessionId;
      if (command === 'export') {
        if (scope === 'demo') throw new TypeError('Swarm demo export unsupported');
        const exportType = String(input.exportType || '');
        if (!SWARM_EXPORT_TYPES.has(exportType)) throw new TypeError('invalid Swarm export type');
        payload.exportType = exportType;
      }
    }
    return payload;
  }

  async function swarmRequest(input, signal) {
    const body = swarmPayload(input);
    const path = '/api/para11ax/swarm';
    const token = getToken();
    if (!token) throw new GatewayHttpError(401, 'unauthorized');
    const response = await fetchImpl(path, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      signal,
      body: JSON.stringify(body),
    });
    const contentType = response.headers.get('content-type') || '';
    if (!response.ok) return readJsonResponse(path, response, null);
    if (body.command !== 'export') return readJsonResponse(path, response, validSwarm);
    if (!contentType.includes('application/octet-stream')) throw new GatewayHttpError(502, 'invalid_swarm_export');
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_SWARM_EXPORT_BYTES) throw new GatewayHttpError(502, 'swarm_export_too_large');
    const data = new Uint8Array(await response.arrayBuffer());
    if (data.byteLength > MAX_SWARM_EXPORT_BYTES) throw new GatewayHttpError(502, 'swarm_export_too_large');
    const rawDisposition = response.headers.get('content-disposition') || '';
    const filenameMatch = rawDisposition.match(/filename="([A-Za-z0-9._-]{1,300})"/);
    const fallback = body.exportType === 'pcap' ? `${body.sessionId}.pcap` : `${body.sessionId}.bin`;
    const durationMs = Number(response.headers.get('x-para11ax-duration-ms'));
    return {
      requestId: response.headers.get('x-para11ax-request-id') || null,
      source: 'greynoise-swarm',
      command: 'export',
      input: { scope: body.scope, sessionId: body.sessionId },
      exportType: body.exportType,
      filename: filenameMatch?.[1] ?? fallback,
      mediaType: 'application/octet-stream',
      bytes: data.byteLength,
      durationMs: Number.isFinite(durationMs) && durationMs >= 0 ? durationMs : null,
      data,
    };
  }

  const client = Object.freeze({
    meta: (signal) => publicRequest('/api/para11ax/meta', { signal, validate: validMeta }),
    health: (signal) => request('/api/para11ax/health', { signal }),
    status: (signal) => request('/api/para11ax/status', { signal }),
    enrich: async (indicator, profile, signal) => {
      const result = await request('/api/para11ax/enrich', {
        method: 'POST',
        body: requestPayload(indicator, profile),
        signal,
        validate: validEnvelope,
      });
      await notifyEnrichmentObservers(result);
      return result;
    },
    provider: async (provider, indicator, signal) => {
      const result = await request('/api/para11ax/provider', {
        method: 'POST',
        body: providerPayload(provider, indicator),
        signal,
        validate: validEnvelope,
      });
      await notifyEnrichmentObservers(result);
      return result;
    },
    batch: async (indicators, profile, signal) => request('/api/para11ax/batch', {
      method: 'POST',
      body: batchPayload(indicators, profile),
      signal,
      validate: validBatch,
    }),
    stix: async (indicator, profile, signal) => request('/api/para11ax/stix', {
      method: 'POST',
      body: requestPayload(indicator, profile),
      signal,
      validate: validStix,
    }),
    userScanner: async (input, signal) => request('/api/para11ax/user-scanner', {
      method: 'POST',
      body: userScannerPayload(input),
      signal,
      validate: validUserScanner,
    }),
    shodan: async (input, signal) => request('/api/para11ax/shodan', {
      method: 'POST',
      body: shodanPayload(input),
      signal,
      validate: validShodan,
    }),
    swarm: swarmRequest,
  });

  latestGatewayClient = client;
  return client;
}

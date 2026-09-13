import { fetchJson } from '../core/fetch-json.js';
import { arr, compact, relation, requireEnv, uniq } from './helpers.js';

const API_ROOT = 'https://api.magnify.modat.io';
const MAX_RELATIONSHIPS = 250;
const MAX_VALUES = 100;

function bounded(values, limit = MAX_VALUES) {
  return uniq(values).slice(0, limit);
}

function invalidResponse(message) {
  return Object.assign(new Error(message), { status: 502 });
}

function noHostResult(input) {
  return {
    observationType: 'internet_exposure',
    verdict: 'no_result',
    attributes: {
      ip: input.value,
      asn: null,
      organization: null,
      country: null,
      hostnames: [],
      ports: [],
      serviceCount: 0,
      serviceTags: [],
      cves: [],
    },
    relationships: [],
    references: ['https://api.magnify.modat.io/docs'],
  };
}

function noDnsResult(input) {
  return {
    observationType: 'passive_dns',
    verdict: 'no_result',
    attributes: {
      fqdn: input.value,
      recordTypes: [],
      addressCount: 0,
      aliasCount: 0,
      nameserverCount: 0,
      mailExchangerCount: 0,
    },
    relationships: [],
    references: ['https://api.magnify.modat.io/docs'],
  };
}

function asnValue(raw) {
  const value = raw?.asn;
  if (value && typeof value === 'object') {
    const number = value.number ?? value.asn ?? value.id;
    if (number !== undefined && number !== null && String(number).trim()) {
      const text = String(number).trim().toUpperCase();
      return text.startsWith('AS') ? text : `AS${text}`;
    }
  }
  if (value !== undefined && value !== null && String(value).trim()) {
    const text = String(value).trim().toUpperCase();
    return text.startsWith('AS') ? text : `AS${text}`;
  }
  const fallback = raw?.autonomous_system?.asn ?? raw?.autonomous_system?.number;
  if (fallback === undefined || fallback === null || !String(fallback).trim()) return null;
  const text = String(fallback).trim().toUpperCase();
  return text.startsWith('AS') ? text : `AS${text}`;
}

function asnOrganization(raw) {
  const value = raw?.asn;
  if (value && typeof value === 'object') return value.organization ?? value.name ?? null;
  return raw?.autonomous_system?.organization ?? raw?.autonomous_system?.name ?? null;
}

function hostnames(raw) {
  return bounded([
    ...arr(raw?.fqdns),
    ...arr(raw?.hostnames),
    ...arr(raw?.names),
  ]);
}

function serviceValues(raw) {
  const services = arr(raw?.services).slice(0, MAX_VALUES);
  const ports = [...new Set(
    services
      .map(item => item?.port)
      .filter(value => Number.isInteger(Number(value)))
      .map(Number),
  )].slice(0, MAX_VALUES);
  const tags = bounded(services.flatMap(item => arr(item?.tags)));
  const cves = bounded(services.flatMap(item => arr(item?.cves).map(cve => typeof cve === 'string' ? cve : cve?.id ?? cve?.cve)));
  return { services, ports, tags, cves };
}

function recordValues(records, names) {
  const groups = names.flatMap(name => arr(records?.[name] ?? records?.[name.toLowerCase()]));
  return groups.slice(0, MAX_VALUES).map(record => ({
    value: typeof record === 'string' ? record : record?.value ?? record?.address ?? record?.target ?? record?.exchange ?? null,
    firstSeen: typeof record === 'object' ? record?.first_seen ?? record?.firstSeen ?? null : null,
    lastSeen: typeof record === 'object' ? record?.last_seen ?? record?.lastSeen ?? null : null,
  })).filter(item => item.value !== null && item.value !== undefined && String(item.value).trim());
}

function latestTimestamp(values) {
  const timestamps = values
    .map(value => value?.lastSeen)
    .filter(Boolean)
    .map(value => Date.parse(value))
    .filter(Number.isFinite);
  return timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : null;
}

async function runIp(input, context, key) {
  const url = `${API_ROOT}/host/search/v1`;
  let raw;
  try {
    raw = await fetchJson(url, {
      ...context,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: `ip:\"${input.value}\"`,
        page: 1,
        page_size: 10,
      }),
      maxBytes: 4_000_000,
    });
  } catch (error) {
    if (error?.status === 404) return noHostResult(input);
    throw error;
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw invalidResponse('invalid Modat host search response');
  const hasPage = Array.isArray(raw.page);
  const hasResults = Array.isArray(raw.results);
  if (!hasPage && !hasResults) throw invalidResponse('invalid Modat host search response');
  const rows = hasPage ? raw.page : raw.results;
  if (!rows.length) return noHostResult(input);
  const host = rows[0];
  if (!host || typeof host !== 'object' || Array.isArray(host)) throw invalidResponse('invalid Modat host result');

  const names = hostnames(host);
  const asn = asnValue(host);
  const { services, ports, tags, cves } = serviceValues(host);
  const hasHostEvidence = Boolean(host?.ip ?? host?.last_seen ?? host?.lastSeen ?? asn) || names.length > 0 || services.length > 0;
  if (!hasHostEvidence) throw invalidResponse('empty Modat host result');

  const relationships = compact([
    ...names.map(name => relation('domain', name, 'hostname')),
    asn ? relation('asn', asn, 'asn') : null,
  ]).slice(0, MAX_RELATIONSHIPS);

  return {
    observationType: 'internet_exposure',
    verdict: 'observed',
    lastSeen: host?.last_seen ?? host?.lastSeen ?? null,
    tags,
    attributes: {
      ip: host?.ip ?? input.value,
      asn,
      organization: asnOrganization(host),
      country: host?.geo?.country_code ?? host?.geo?.country ?? host?.country_code ?? null,
      hostnames: names,
      ports,
      serviceCount: services.length,
      serviceTags: tags,
      cves,
    },
    relationships,
    references: ['https://api.magnify.modat.io/docs'],
  };
}

async function runDomain(input, context, key) {
  const url = `${API_ROOT}/dns/zones/${encodeURIComponent(input.value)}/v1`;
  let raw;
  try {
    raw = await fetchJson(url, {
      ...context,
      method: 'GET',
      headers: { Authorization: `Bearer ${key}` },
      maxBytes: 4_000_000,
    });
  } catch (error) {
    if (error?.status === 404) return noDnsResult(input);
    throw error;
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw invalidResponse('invalid Modat DNS response');
  if (!raw.records || typeof raw.records !== 'object' || Array.isArray(raw.records)) throw invalidResponse('empty Modat DNS response');

  const records = raw.records;
  const addresses = recordValues(records, ['A', 'AAAA']);
  const aliases = recordValues(records, ['CNAME']);
  const nameservers = recordValues(records, ['NS']);
  const mail = recordValues(records, ['MX']);
  const all = [...addresses, ...aliases, ...nameservers, ...mail];
  const relationships = compact([
    ...addresses.map(item => relation('ip', item.value, 'resolves_to')),
    ...aliases.map(item => relation('domain', item.value, 'cname')),
    ...nameservers.map(item => relation('domain', item.value, 'nameserver')),
    ...mail.map(item => relation('domain', item.value, 'mail_exchanger')),
  ]).slice(0, MAX_RELATIONSHIPS);

  return {
    observationType: 'passive_dns',
    verdict: 'observed',
    lastSeen: raw?.last_seen ?? raw?.lastSeen ?? latestTimestamp(all),
    tags: [],
    attributes: {
      fqdn: raw?.fqdn ?? input.value,
      recordTypes: Object.keys(records).filter(keyName => Array.isArray(records[keyName]) && records[keyName].length).slice(0, 20),
      addressCount: addresses.length,
      aliasCount: aliases.length,
      nameserverCount: nameservers.length,
      mailExchangerCount: mail.length,
    },
    relationships,
    references: ['https://api.magnify.modat.io/docs'],
  };
}

export const modatProvider = Object.freeze({
  name: 'modat',
  types: ['ip', 'domain'],
  requiredEnv: 'MODAT_API_KEY',
  cacheTtlMs: 21_600_000,
  negativeCacheTtlMs: 3_600_000,
  costClass: 'quota',
  timeoutMs: 7_000,
  parserVersion: '2026-08-23.1',
  async run(input, context = {}) {
    const key = requireEnv(context, 'MODAT_API_KEY');
    if (input?.type === 'ip') return runIp(input, context, key);
    if (input?.type === 'domain') return runDomain(input, context, key);
    throw Object.assign(new Error('unsupported Modat indicator type'), { status: 400 });
  },
});

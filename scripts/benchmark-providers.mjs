#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { admitToAutomaticWorkflow, summarizeProviderBenchmark } from '../src/core/provider-admission.js';

const DEFAULT_CORPUS = 'config/benchmark-corpus.example.json';
const DEFAULT_BASE_URL = 'http://127.0.0.1:3000';
const PROVIDER_PATH = '/api/para11ax/provider';
const CREDENTIAL_KEY_RE = /(?:authorization|password|secret|token|api[_-]?key)/i;

function usage() {
  return [
    'Usage: node scripts/benchmark-providers.mjs [--corpus <path>] [--live] [--base-url <url>] [--pretty]',
    '',
    'Default mode summarizes recorded local observations only.',
    'With --live, requests are sent only to the existing authenticated PARA11AX provider gateway.',
    'Gateway credentials are read from the environment variable named by gateway.tokenEnv (default PARA11AX_TOKEN).',
  ].join('\n');
}

function parseArgs(argv) {
  const options = { corpus: DEFAULT_CORPUS, live: false, pretty: false, baseUrl: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--live') options.live = true;
    else if (arg === '--pretty') options.pretty = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--corpus') options.corpus = argv[++index];
    else if (arg === '--base-url') options.baseUrl = argv[++index];
    else throw new TypeError(`unsupported argument: ${arg}`);
  }
  if (!options.corpus) throw new TypeError('--corpus requires a path');
  if (argv.includes('--base-url') && !options.baseUrl) throw new TypeError('--base-url requires a URL');
  return Object.freeze(options);
}

function assertCredentialFree(value, path = '$') {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertCredentialFree(entry, `${path}[${index}]`));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (CREDENTIAL_KEY_RE.test(key) && !key.endsWith('Env')) {
      throw new TypeError(`credential-like field is forbidden in benchmark corpus: ${path}.${key}`);
    }
    assertCredentialFree(child, `${path}.${key}`);
  }
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function evidenceFingerprint(evidence) {
  if (typeof evidence?.fingerprint === 'string' && evidence.fingerprint) return evidence.fingerprint;
  return canonical({ provider: evidence?.provider ?? evidence?.source ?? null, observation: evidence?.observation ?? null });
}

function edgeFingerprint(edge) {
  if (typeof edge?.fingerprint === 'string' && edge.fingerprint) return edge.fingerprint;
  return canonical({
    source: edge?.source ?? edge?.from ?? edge?.sourceId ?? null,
    type: edge?.type ?? edge?.relationship ?? edge?.kind ?? null,
    target: edge?.target ?? edge?.to ?? edge?.targetId ?? null,
  });
}

function responseEdges(body) {
  const candidates = [body?.graph?.edges, body?.intelligence?.relationships, body?.relationships];
  return candidates.find(Array.isArray) ?? [];
}

function resolveGatewayBase(value) {
  const url = new URL(value || DEFAULT_BASE_URL);
  if (!['http:', 'https:'].includes(url.protocol)) throw new TypeError('gateway base URL must use http or https');
  url.pathname = '/';
  url.search = '';
  url.hash = '';
  return url;
}

async function callProvider({ baseUrl, token, provider, indicator, type }) {
  const endpoint = new URL(PROVIDER_PATH, baseUrl);
  const started = performance.now();
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ provider, indicator, ...(type ? { type } : {}) }),
      redirect: 'error',
    });
    const latencyMs = Math.max(0, Math.round(performance.now() - started));
    let body = null;
    try { body = await response.json(); } catch {}
    if (!response.ok || !body || typeof body !== 'object') return { latencyMs, status: 'error', body: null };
    return { latencyMs, status: 'ok', body };
  } catch {
    return { latencyMs: Math.max(0, Math.round(performance.now() - started)), status: 'error', body: null };
  }
}

async function collectLiveObservations(providerSpec, { baseUrl, token }) {
  const cases = Array.isArray(providerSpec.cases) ? providerSpec.cases : [];
  if (cases.length === 0) throw new TypeError(`live provider ${providerSpec.name} requires at least one case`);
  const seenFacts = new Set(providerSpec.baselineEvidenceFingerprints ?? []);
  const seenEdges = new Set(providerSpec.baselineGraphEdges ?? []);
  const observations = [];

  for (const benchmarkCase of cases) {
    const repeats = Math.max(1, Math.min(20, Number(benchmarkCase.repeats) || 1));
    for (let repeat = 0; repeat < repeats; repeat += 1) {
      const result = await callProvider({
        baseUrl,
        token,
        provider: providerSpec.name,
        indicator: benchmarkCase.indicator,
        type: benchmarkCase.type,
      });
      if (result.status === 'error') {
        observations.push({ latencyMs: result.latencyMs, status: 'error', uniqueFacts: 0, uniqueGraphEdges: 0, decisionChanging: false, materialUniqueObservations: 0 });
        continue;
      }

      const evidence = Array.isArray(result.body.evidence) ? result.body.evidence : [];
      const edges = responseEdges(result.body);
      let uniqueFacts = 0;
      let uniqueGraphEdges = 0;
      for (const item of evidence) {
        const fingerprint = evidenceFingerprint(item);
        if (!seenFacts.has(fingerprint)) { seenFacts.add(fingerprint); uniqueFacts += 1; }
      }
      for (const edge of edges) {
        const fingerprint = edgeFingerprint(edge);
        if (!seenEdges.has(fingerprint)) { seenEdges.add(fingerprint); uniqueGraphEdges += 1; }
      }
      const noResult = result.body.status === 'no_result' || (evidence.length === 0 && edges.length === 0);
      observations.push({
        latencyMs: result.latencyMs,
        status: noResult ? 'no_result' : 'observed',
        uniqueFacts,
        uniqueGraphEdges,
        decisionChanging: benchmarkCase.decisionChanging === true && !noResult,
        materialUniqueObservations: uniqueFacts + uniqueGraphEdges,
      });
    }
  }

  return observations;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { process.stdout.write(`${usage()}\n`); return; }

  const corpusPath = resolve(options.corpus);
  const corpus = JSON.parse(await readFile(corpusPath, 'utf8'));
  assertCredentialFree(corpus);
  if (!corpus.thresholds || typeof corpus.thresholds !== 'object') throw new TypeError('benchmark corpus thresholds are required');
  if (!Array.isArray(corpus.providers) || corpus.providers.length === 0) throw new TypeError('benchmark corpus providers must be a non-empty array');

  let baseUrl = null;
  let token = null;
  if (options.live) {
    baseUrl = resolveGatewayBase(options.baseUrl ?? corpus.gateway?.baseUrl ?? process.env.PARA11AX_BASE_URL ?? DEFAULT_BASE_URL);
    const tokenEnv = String(corpus.gateway?.tokenEnv ?? 'PARA11AX_TOKEN');
    token = process.env[tokenEnv];
    if (!token) throw new TypeError(`live benchmark requires gateway credential in ${tokenEnv}`);
  }

  const providers = {};
  for (const providerSpec of corpus.providers) {
    const name = String(providerSpec?.name ?? '').trim();
    if (!/^[a-z0-9-]{1,64}$/.test(name)) throw new TypeError(`invalid provider name: ${name || '<empty>'}`);
    const observations = options.live
      ? await collectLiveObservations(providerSpec, { baseUrl, token })
      : providerSpec.observations;
    const metrics = summarizeProviderBenchmark(observations);
    providers[name] = Object.freeze({ metrics, admission: admitToAutomaticWorkflow(metrics, corpus.thresholds) });
  }

  const output = Object.freeze({
    schemaVersion: 1,
    mode: options.live ? 'live_gateway' : 'recorded',
    corpus: options.corpus,
    providers: Object.freeze(providers),
  });
  process.stdout.write(`${JSON.stringify(output, null, options.pretty ? 2 : 0)}\n`);
}

main().catch(error => {
  process.stderr.write(`benchmark-providers: ${error?.message ?? String(error)}\n`);
  process.exitCode = 1;
});

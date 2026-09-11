import { MCP_OAUTH_SCOPE } from './oauth.js';

const TOOL_METADATA = Object.freeze({
  para11ax_capabilities: {
    description: 'Use this when you need to inspect the authenticated PARA11AX capability catalog, health, status, metadata, or remotely exposed registered commands before choosing another tool.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true },
  },
  para11ax_enrich: {
    description: 'Use this when you need policy-bound Evidence v2 enrichment for one observable through the configured PARA11AX intelligence providers.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true, idempotentHint: false },
  },
  para11ax_batch: {
    description: 'Use this when you need bounded Evidence v2 enrichment for 1 to 20 observables in one request.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true, idempotentHint: false },
  },
  para11ax_provider: {
    description: 'Use this when you need to run one exact registered intelligence provider against one observable through the bounded provider gateway.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true, idempotentHint: false },
  },
  para11ax_shodan: {
    description: 'Use this when you need bounded read-only Shodan host, search, count, stats, domain, or API-info operations.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true, idempotentHint: false },
  },
  para11ax_swarm: {
    description: 'Use this when you need bounded GreyNoise Project Swarm session search, retrieval, pivot, timeseries, diff, or export operations.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true, idempotentHint: false },
  },
  para11ax_user_scan: {
    description: 'Use this when you need authorized defensive identity OSINT for one email address or username, and you have explicit permission to use the isolated, bounded User Scanner worker. Treat matches as investigative indicators, not proof of identity or activity.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true, idempotentHint: false },
  },
  para11ax_stix: {
    description: 'Use this when you need a deterministic STIX 2.1 bundle for one observable after normal PARA11AX enrichment.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true, idempotentHint: false },
  },
  para11ax_mission: {
    description: 'Use this when you need the stateless mission, hunt, KQL-validation, result-analysis, or ServiceNow-projection workflow with explicit workspace state passed in and returned on every call.',
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: false },
  },
  para11ax_investigation: {
    description: 'Use this when you need to create, inspect, mutate, report, import, or export an Investigation Workspace v2 using explicit state-in and state-out rather than hidden server persistence.',
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: false },
  },
  para11ax_case: {
    description: 'Use this when you need to create or operate a portable analyst case using explicit case state, notes, pins, snapshots, graphs, diffs, or export without hidden server persistence.',
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: false },
  },
  para11ax_report: {
    description: 'Use this when you need to render, inspect quality, or build a manifest for deterministic enrichment or investigation reports without filesystem access.',
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true },
  },
  para11ax_command: {
    description: 'Use this when no dedicated PARA11AX MCP tool matches and you need one exact server-safe registered command by command id; local-admin, filesystem, credential-template, browser-session, and host-shell capabilities remain blocked.',
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true, idempotentHint: false },
  },
});

const USER_SCAN_SCHEMA = Object.freeze({
  type: 'object',
  properties: {
    scanType: { type: 'string', description: 'Identity target type.', enum: ['email', 'username'] },
    target: { type: 'string', description: 'Authorized identity target.' },
    category: { type: 'string', description: 'Optional bounded User Scanner category filter.' },
    module: { type: 'string', description: 'Optional bounded User Scanner module filter.' },
    crossScan: { type: 'boolean', description: 'Whether to enable the worker cross-scan option.' },
    noNsfw: { type: 'boolean', description: 'Whether to exclude NSFW sources.' },
  },
  required: ['scanType', 'target'],
  additionalProperties: false,
});

export function applyChatGptToolMetadata(tools) {
  for (const tool of tools) {
    const metadata = TOOL_METADATA[tool.name];
    if (!metadata) continue;
    tool.description = metadata.description;
    tool.annotations = { ...metadata.annotations };
    tool.securitySchemes = [{ type: 'oauth2', scopes: [MCP_OAUTH_SCOPE] }];
    if (tool.name === 'para11ax_user_scan') tool.inputSchema = USER_SCAN_SCHEMA;
  }
  return tools;
}

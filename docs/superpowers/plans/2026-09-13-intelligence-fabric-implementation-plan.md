# PARA11AX Intelligence Fabric Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the approved multi-lane PARA11AX intelligence fabric so existing enrichment remains backward compatible while graph, search, owned-asset, sensitive, supply-chain, malware, and knowledge capabilities can be integrated safely and incrementally.

**Architecture:** Preserve the existing provider registry, fixed-host transport, Evidence v2 normalization, scheduler, HTTP/MCP/CLI surfaces, and investigation workflows. Add validated capability policy, new observable classes, explicit authorization context, deterministic secondary pivots, distribution enforcement, and provider-family abstractions. Existing providers are deepened before new vendors are admitted; sensitive and owned-asset capabilities are never reachable through ordinary enrichment.

**Tech Stack:** Node.js 24.x ESM, built-in `node:test`, JSON provider/observable manifests, Vercel deployment, MCP, STIX 2.1 export, GitHub Actions/CodeQL.

**Spec:** `docs/superpowers/specs/2026-09-13-intelligence-fabric-design.md`

## Global Constraints

- Preserve deterministic classification and strict canonicalization.
- Preserve fixed HTTPS egress and prohibit caller-controlled outbound hosts.
- Preserve Evidence v2 provenance and partial-failure semantics.
- Ordinary `enrich`, `batch`, and `provider` behavior must remain backward compatible unless explicitly versioned.
- `full` enrichment must never imply permission for `monitor`, `analysis`, or `sensitive` modes.
- No secret reflection in responses, references, logs, generated artifacts, or Git history.
- Raw secret material is never a generic observable; only privacy-preserving `secret-fingerprint` values are accepted.
- Provider failure must never become negative intelligence.
- Knowledge observations must never increase maliciousness or attribution confidence.
- All calls, pages, graph expansions, bodies, relationships, and outputs remain bounded.
- Missing optional credentials produce `unconfigured`, not runtime failure.
- Production promotion remains protected-PR only; exact production SHA must be verified after merge.

---

## File Structure and Ownership

Core fabric files:

- Modify `config/providers.json` — single provider/capability policy source.
- Modify `config/observables.json` — observable registry policy.
- Modify `src/providers/manifest.js` — validate provider policy fields.
- Modify `src/providers/metadata.js` — expose validated policy on adapters.
- Modify `src/core/observable-registry.js` — validate new observable categories/canonicalizers.
- Modify `src/core/validate.js` — strict canonicalization for new observables.
- Create `src/core/intelligence-policy.js` — mode/sensitivity/authorization admission decisions.
- Create `src/core/authorization-context.js` — immutable trusted authorization-context normalization.
- Create `src/core/intelligence-planner.js` — deterministic secondary pivot planning.
- Modify `src/core/semantics.js` — semantic-class registration.
- Modify `src/core/evidence-semantics.js` — evidence-role rules including knowledge-only semantics.
- Modify `src/core/normalize.js` — attach execution/distribution metadata.
- Modify `src/core/evidence-graph.js` — canonicalize/dedupe/cap new relationship types.
- Modify `src/core/orchestrator.js` — enforce policy before provider execution and expose optional pivot phase.
- Modify `src/workflows.js` / `src/profiles.js` — baseline fan-out remains static and safe.
- Modify `src/app.js` — capability metadata plus normalized intelligence endpoint/handler.
- Modify `src/export/stix.js` — enforce distribution and support only valid new STIX mappings.
- Modify `src/mcp/server.js` / `src/mcp/chatgpt-tool-metadata.js` — one normalized intelligence tool surface.
- Modify `bin/para11ax.mjs` — CLI namespace parity.

Provider expansion files:

- Modify `src/providers/virustotal.js`
- Modify `src/providers/urlscan.js`
- Modify `src/providers/censys.js`
- Create `src/providers/vulncheck.js`
- Create `src/providers/deps-dev.js`
- Create `src/providers/sslbl.js`
- Create `src/providers/yaraify.js`
- Create `src/providers/d3fend.js`
- Create `src/providers/wayback-cdx.js`
- Create `src/providers/mwdb.js`
- Create `src/providers/chainabuse.js`
- Create `src/providers/gitguardian-hmsl.js`
- Create `src/providers/shadowserver.js`
- Create `src/providers/microsoft-ti.js`
- Create `src/providers/dnsdb.js`
- Create `src/providers/validin.js`
- Create `src/providers/spur.js`
- Create `src/providers/netify.js`
- Create `src/providers/team-cymru.js`
- Create `src/providers/recorded-future.js`
- Create `src/providers/google-ti.js`
- Create `src/providers/darkweb-family.js`
- Modify `src/providers/index.js`

Tests use focused `node:test` files under `test/` and existing full-suite gates.

---

### Task 1: Provider Capability Policy Contract

**Files:**
- Modify: `src/providers/manifest.js`
- Modify: `src/providers/metadata.js`
- Modify: `config/providers.json`
- Test: `test/provider-capability-policy.test.js`

**Interfaces:**
- Produces `adapter.mode`, `adapter.fanoutEligible`, `adapter.sensitivity`, `adapter.authorization`, `adapter.retentionClass`, `adapter.distribution`, `adapter.providerFamily`, `adapter.maxPages`, and `adapter.maxRelationships`.
- Existing adapters default explicitly in `config/providers.json`; there are no runtime implicit defaults for policy-sensitive fields.

- [ ] **Step 1: Write failing policy-validation tests**

Create `test/provider-capability-policy.test.js` with table-driven tests proving accepted and rejected enum values. Include an assertion that every currently registered provider has `mode: 'enrich'`, `fanoutEligible: true|false`, `sensitivity: 'public'`, `authorization: 'none'`, and a retention class.

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateProviderPolicy } from '../src/providers/manifest.js';

const base = {
  displayName: 'Fixture', credentialEnv: null, optionalCredential: false,
  authType: 'none', tier: 1, costClass: 'free', types: ['domain'],
  observationTypes: ['dns_resolution'], timeoutMs: 1000, cacheTtlMs: 1000,
  negativeCacheTtlMs: 1000, maxResponseBytes: 1024, fixedHosts: ['example.org'],
  methods: ['GET'], protocols: ['https:'], parserVersion: '1',
  sourceUrl: 'https://example.org/docs', distribution: 'shareable', active: true,
  sourceRole: 'first_party', freshnessClass: 'live', admissionVersion: 'v8.1',
  executionPolicy: 'v8.1', mode: 'enrich', fanoutEligible: true,
  sensitivity: 'public', authorization: 'none', retentionClass: 'normal',
};

test('accepts validated intelligence capability policy', () => {
  assert.equal(validateProviderPolicy('fixture', base).mode, 'enrich');
});

test('rejects sensitive capability with automatic fanout', () => {
  assert.throws(() => validateProviderPolicy('fixture', {
    ...base, mode: 'sensitive', sensitivity: 'pii', authorization: 'explicit_case', fanoutEligible: true,
  }));
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `node --test test/provider-capability-policy.test.js`
Expected: FAIL because the new policy fields are not yet validated/exposed.

- [ ] **Step 3: Implement manifest validation**

Add enum sets in `src/providers/manifest.js`:

```js
const MODES = new Set(['enrich','graph','search','monitor','analysis','knowledge','sensitive']);
const SENSITIVITY = new Set(['public','owned_asset','pii','credential','secret','sample']);
const AUTHORIZATION = new Set(['none','tenant','verified_domain','owned_network','explicit_case','explicit_action']);
const RETENTION = new Set(['normal','restricted','ephemeral','no_store']);
```

Reject `fanoutEligible === true` unless `mode === 'enrich' && authorization === 'none' && sensitivity === 'public'`. Validate optional integer bounds `maxPages` in `1..100` and `maxRelationships` in `1..1000` when present. Preserve the existing `distribution` field as the only export-policy source of truth.

- [ ] **Step 4: Populate existing provider policies and expose metadata**

Update every entry in `config/providers.json` with explicit safe values. In `src/providers/metadata.js`, copy the validated fields onto wrapped adapters. Do not change current workflow membership in this task.

- [ ] **Step 5: Run focused and invariant tests**

Run:
`node --test test/provider-capability-policy.test.js test/provider-manifest*.test.js test/provider-contract*.test.js`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add config/providers.json src/providers/manifest.js src/providers/metadata.js test/provider-capability-policy.test.js
git commit -m "feat: add intelligence capability policy"
```

---

### Task 2: New Observable Canonicalization

**Files:**
- Modify: `config/observables.json`
- Modify: `src/core/observable-registry.js`
- Modify: `src/core/validate.js`
- Test: `test/intelligence-observables.test.js`

**Interfaces:**
- `classifyIndicator(input)` continues returning `{ value, type }`.
- Adds canonical types: `email`, `package`, `tls-fingerprint`, `crypto-address`, `secret-fingerprint`, `legal-entity`, `username`.
- Ambiguous formats are rejected; prefixed formats are used where collision risk exists.

- [ ] **Step 1: Write failing canonicalization tests**

Test representative accepted values:

```js
assert.deepEqual(classifyIndicator('analyst@example.com'), { value: 'analyst@example.com', type: 'email' });
assert.deepEqual(classifyIndicator('pkg:npm/%40scope/name@1.2.3'), { value: 'pkg:npm/%40scope/name@1.2.3', type: 'package' });
assert.deepEqual(classifyIndicator('ja3:72a589da586844d7f0818ce684948eea'), { value: 'ja3:72a589da586844d7f0818ce684948eea', type: 'tls-fingerprint' });
assert.deepEqual(classifyIndicator('secret-sha256:' + 'a'.repeat(64)), { value: 'secret-sha256:' + 'a'.repeat(64), type: 'secret-fingerprint' });
assert.deepEqual(classifyIndicator('user:para11ax_qa'), { value: 'para11ax_qa', type: 'username' });
```

Also prove malformed PURLs, raw secrets, unprefixed usernames, malformed fingerprints, whitespace-bearing emails, and ambiguous crypto strings fail.

- [ ] **Step 2: Run focused test and verify RED**

Run: `node --test test/intelligence-observables.test.js`
Expected: FAIL with unsupported indicator errors.

- [ ] **Step 3: Extend observable manifest validators**

Add categories `identity`, `supply_chain`, and `financial_context` only if needed by the concrete observable entries. Extend canonicalization enum with exact canonicalizer names rather than a generic free-form option.

- [ ] **Step 4: Implement strict parsers in `validate.js`**

Use dedicated functions such as `validEmail`, `validPurl`, `validTlsFingerprint`, `validSecretFingerprint`, `validUsername`. Crypto addresses must require network-prefixed input such as `btc:<address>` or `eth:<address>` to prevent ambiguous classification.

- [ ] **Step 5: Run tests**

Run: `node --test test/intelligence-observables.test.js test/asn-cidr.test.js test/certificate-observable.test.js`
Expected: PASS with legacy classifiers unchanged.

- [ ] **Step 6: Commit**

```bash
git add config/observables.json src/core/observable-registry.js src/core/validate.js test/intelligence-observables.test.js
git commit -m "feat: add intelligence observables"
```

---

### Task 3: Trusted Authorization Context and Policy Gate

**Files:**
- Create: `src/core/authorization-context.js`
- Create: `src/core/intelligence-policy.js`
- Test: `test/intelligence-policy.test.js`

**Interfaces:**
- Produces `normalizeAuthorizationContext(input)` returning a deeply frozen trusted context.
- Produces `authorizeCapability({ adapter, requestedMode, authz })` returning `{ allowed, reason }`.

- [ ] **Step 1: Write failing policy tests**

Cover: ordinary enrich allowed; sensitive denied without explicit case; owned-network monitor denied without server-approved CIDR scope; analysis denied without explicit action; caller-supplied strings alone cannot self-authorize.

```js
assert.deepEqual(authorizeCapability({ adapter: enrichAdapter, requestedMode: 'enrich', authz: normalizeAuthorizationContext({}) }), { allowed: true, reason: 'allowed' });
assert.equal(authorizeCapability({ adapter: sensitiveAdapter, requestedMode: 'sensitive', authz: normalizeAuthorizationContext({}) }).reason, 'explicit_case_required');
```

- [ ] **Step 2: Verify RED**

Run: `node --test test/intelligence-policy.test.js`
Expected: module-not-found failure.

- [ ] **Step 3: Implement immutable authorization context**

Context fields are server-generated only: `principal`, `caseId`, `verifiedDomains`, `ownedCidrs`, `tenant`, `explicitAnalysis`, `requestedMode`. Normalize arrays, bound counts, freeze recursively, and reject malformed domains/CIDRs rather than silently widening scope.

- [ ] **Step 4: Implement deterministic authorization matrix**

Map each `authorization` enum to exact requirements. No provider-specific custom bypass is allowed inside adapters.

- [ ] **Step 5: Run test and commit**

```bash
node --test test/intelligence-policy.test.js
git add src/core/authorization-context.js src/core/intelligence-policy.js test/intelligence-policy.test.js
git commit -m "feat: enforce intelligence authorization policy"
```

---

### Task 4: Semantic Classes, Distribution, and Evidence Metadata

**Files:**
- Modify: `src/core/semantics.js`
- Modify: `src/core/evidence-semantics.js`
- Modify: `src/core/normalize.js`
- Modify: `src/export/stix.js`
- Test: `test/intelligence-semantics.test.js`
- Test: `test/distribution-policy.test.js`

**Interfaces:**
- Normalized evidence gains `policy: { mode, sensitivity, retentionClass, distribution }`.
- `evidenceRole` distinguishes knowledge-only evidence so it cannot affect threat decisions.
- STIX export excludes `internal_only` evidence and only uses allowed summaries/references for `summary_only` if that distribution value is introduced.

- [ ] **Step 1: Write failing semantic and distribution tests**

Assert new kinds map deterministically: `credential_exposure`, `infostealer_exposure`, `passive_dns_history`, `domain_ownership_history`, `malware_configuration`, `malware_similarity`, `supply_chain`, `anonymization_infrastructure`, `web_archive_observation`, `secret_exposure`, `crypto_abuse`, `legal_entity_context`, `tls_malware_infrastructure`, `exploit_maturity`, `underground_mention`, `defensive_knowledge`.

Assert `defensive_knowledge` returns role `knowledge_only` regardless of source role.

Assert STIX external references from evidence marked `internal_only` are absent.

- [ ] **Step 2: Verify RED**

Run: `node --test test/intelligence-semantics.test.js test/distribution-policy.test.js`
Expected: FAIL on unknown semantics/policy metadata.

- [ ] **Step 3: Implement mappings and normalization metadata**

Extend semantic tables explicitly. In `normalizeEvidence`, attach adapter policy supplied by orchestrator metadata rather than trusting provider-returned policy fields.

- [ ] **Step 4: Enforce export policy centrally**

Filter evidence before STIX reference extraction. Preserve the primary observable export when the observable itself is shareable; only evidence-derived restricted content is removed.

- [ ] **Step 5: Run focused tests and commit**

```bash
node --test test/intelligence-semantics.test.js test/distribution-policy.test.js test/stix*.test.js
git add src/core/semantics.js src/core/evidence-semantics.js src/core/normalize.js src/export/stix.js test/intelligence-semantics.test.js test/distribution-policy.test.js
git commit -m "feat: add intelligence evidence policy semantics"
```

---

### Task 5: Deterministic Intelligence Planner and Graph Bounds

**Files:**
- Create: `src/core/intelligence-planner.js`
- Modify: `src/core/evidence-graph.js`
- Modify: `src/core/orchestrator.js`
- Test: `test/intelligence-planner.test.js`
- Test: `test/intelligence-graph-bounds.test.js`

**Interfaces:**
- `planPivots({ type, evidence, relationships, candidates, authz, budget }) -> readonly PivotPlan[]`
- A `PivotPlan` is `{ provider, mode, input: { type, value }, reason }`.
- Planner is rules-based and deterministic; no model call or arbitrary recursive expansion.

- [ ] **Step 1: Write RED tests for planner behavior**

Prove no pivots when baseline evidence is empty; a certificate relationship can admit a configured graph-capable certificate-history provider; a CVE with unresolved exploit maturity can admit VulnCheck; duplicated semantic candidates collapse to the highest-priority provider; sensitive candidates remain denied without authorization.

- [ ] **Step 2: Write RED tests for graph sanitation**

Prove markup is stripped/rejected, malformed targets are rejected, duplicate edges collapse, and expansion stops at configured relationship limits.

- [ ] **Step 3: Implement planner**

Use static rules keyed by source observable type and relationship target type. Consume provider scheduler metadata and policy; never inspect raw provider JSON. Require a remaining call/deadline budget before admitting any pivot.

- [ ] **Step 4: Integrate optional phase-2 execution**

Add an explicit orchestrator option such as `pivotMode: 'off' | 'bounded'`, default `off` for current `enrich` backward compatibility. The future intelligence endpoint will request `bounded`; existing enrichment stays phase-1 only until deliberately changed.

- [ ] **Step 5: Run tests and commit**

```bash
node --test test/intelligence-planner.test.js test/intelligence-graph-bounds.test.js test/orchestrator*.test.js
git add src/core/intelligence-planner.js src/core/evidence-graph.js src/core/orchestrator.js test/intelligence-planner.test.js test/intelligence-graph-bounds.test.js
git commit -m "feat: add bounded intelligence pivot planner"
```

---

### Task 6: Intelligence HTTP/MCP/CLI Surface

**Files:**
- Modify: `src/app.js`
- Modify: `src/core/capability-registry.js`
- Modify: `src/mcp/server.js`
- Modify: `src/mcp/chatgpt-tool-metadata.js`
- Modify: `bin/para11ax.mjs`
- Test: `test/intelligence-api.test.js`
- Test: `test/mcp-intelligence-tool.test.js`

**Interfaces:**
- Add one normalized operation surface with operations: `pivot`, `search`, `identity`, `asset`, `supply_chain`, `malware`, `knowledge`, `providers`.
- Keep existing top-level MCP tools intact.

- [ ] **Step 1: Write failing API schema tests**

Assert unsupported fields fail, unsupported operations fail, normal enrichment endpoints cannot pass authorization claims, and `providers` exposes mode/sensitivity/authorization metadata without secrets.

- [ ] **Step 2: Write failing MCP conformance tests**

Require one tool such as `para11ax_intelligence` with an operation discriminator and bounded operation-specific schemas. Existing 13 tool contracts must remain present.

- [ ] **Step 3: Implement app handler and capability registry**

The handler derives trusted authorization context from server-side session/config input. It dispatches only registered capabilities through the same registry/egress/normalization path.

- [ ] **Step 4: Wire MCP and CLI**

Map MCP/CLI requests to the normalized handler; do not duplicate provider execution logic inside `src/mcp/server.js` or `bin/para11ax.mjs`.

- [ ] **Step 5: Run tests and commit**

```bash
node --test test/intelligence-api.test.js test/mcp-intelligence-tool.test.js test/mcp-*.test.js test/app*.test.js
git add src/app.js src/core/capability-registry.js src/mcp/server.js src/mcp/chatgpt-tool-metadata.js bin/para11ax.mjs test/intelligence-api.test.js test/mcp-intelligence-tool.test.js
git commit -m "feat: expose intelligence capability surface"
```

---

### Task 7: Deepen VirusTotal Relationships

**Files:**
- Modify: `src/providers/virustotal.js`
- Modify: `config/providers.json`
- Test: `test/virustotal-relationships.test.js`

**Interfaces:**
- Point lookup remains unchanged.
- Add explicit bounded graph capability that returns normalized relationships only from documented VT relationship endpoints.

- [ ] **Step 1: Write fixture-based RED tests**

Cover domain resolutions, communicating/contacted files, contacted domains/IPs, certificate relationships, pagination cap, 404 no-result, 403 entitlement error, malformed relationship objects, and dedupe.

- [ ] **Step 2: Implement relationship request builder and parser**

Keep fixed host `www.virustotal.com`, bound result counts, and reuse the existing credential. Relationship capability must not execute through normal automatic `enrich` unless the planner admits it.

- [ ] **Step 3: Run and commit**

```bash
node --test test/virustotal-relationships.test.js test/virustotal*.test.js
git add src/providers/virustotal.js config/providers.json test/virustotal-relationships.test.js
git commit -m "feat: add VirusTotal graph relationships"
```

---

### Task 8: Deepen urlscan and Censys

**Files:**
- Modify: `src/providers/urlscan.js`
- Modify: `src/providers/censys.js`
- Modify: `config/providers.json`
- Test: `test/urlscan-deep-result.test.js`
- Test: `test/censys-search-history.test.js`

**Interfaces:**
- urlscan deep parser adds bounded redirect, request-host, file-hash, TLS/certificate, technology, and final-destination relationships.
- Censys adds explicit search/history methods while preserving current point lookup.

- [ ] **Step 1: Write urlscan RED fixtures**

Include `<mark>`-style or other external markup in fixture values and assert canonical graph outputs contain none.

- [ ] **Step 2: Implement urlscan deep result parsing**

Fetch result detail only in graph mode, never for every search row automatically. Cap requests and relationships.

- [ ] **Step 3: Write Censys RED fixtures**

Cover host search, certificate search, certificate-to-host history, entitlement denial, malformed resource schema, and pagination cap.

- [ ] **Step 4: Implement Censys capabilities**

Reuse bearer auth and fixed `api.platform.censys.io` host. Preserve existing `certificate_metadata` and `internet_exposure` behavior.

- [ ] **Step 5: Run and commit**

```bash
node --test test/urlscan-deep-result.test.js test/censys-search-history.test.js test/webamon-highlight-sanitization.test.js
git add src/providers/urlscan.js src/providers/censys.js config/providers.json test/urlscan-deep-result.test.js test/censys-search-history.test.js
git commit -m "feat: deepen urlscan and Censys pivots"
```

---

### Task 9: Exploit Maturity and Supply-Chain Providers

**Files:**
- Create: `src/providers/vulncheck.js`
- Create: `src/providers/deps-dev.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Modify: `src/workflows.js`
- Test: `test/vulncheck.test.js`
- Test: `test/deps-dev.test.js`

**Interfaces:**
- VulnCheck supports `cve` and emits `exploit_maturity`.
- deps.dev supports `package` and emits `supply_chain` relationships.

- [ ] **Step 1: Write VulnCheck RED tests**

Cover validated exploit presence, exploit maturity fields, no-result, auth/entitlement errors, and relationship emission to actor/ransomware context only when present in source data.

- [ ] **Step 2: Implement VulnCheck adapter**

Use fixed documented API host and bounded JSON responses. Community/XDB data may be fanout-eligible only if policy/latency tests justify it; otherwise keep graph/search explicit.

- [ ] **Step 3: Write deps.dev RED tests**

Cover a PURL resolving to package version, direct dependencies, transitive dependency metadata, vulnerability/advisory links, no-result, malformed package identifiers, and edge cap.

- [ ] **Step 4: Implement deps.dev adapter and package workflow**

Keep direct and transitive relationship types distinguishable.

- [ ] **Step 5: Run and commit**

```bash
node --test test/vulncheck.test.js test/deps-dev.test.js test/intelligence-observables.test.js
git add src/providers/vulncheck.js src/providers/deps-dev.js src/providers/index.js config/providers.json src/workflows.js test/vulncheck.test.js test/deps-dev.test.js
git commit -m "feat: add exploit maturity and supply chain intelligence"
```

---

### Task 10: TLS, Malware Similarity, Malware Configuration, and Historical Web

**Files:**
- Create: `src/providers/sslbl.js`
- Create: `src/providers/yaraify.js`
- Create: `src/providers/mwdb.js`
- Create: `src/providers/wayback-cdx.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Modify: `src/workflows.js`
- Test: `test/sslbl.test.js`
- Test: `test/yaraify.test.js`
- Test: `test/mwdb.test.js`
- Test: `test/wayback-cdx.test.js`

**Interfaces:**
- SSLBL/YARAify emit supporting `tls_malware_infrastructure` / `malware_similarity` evidence.
- MWDB emits `malware_configuration` with bounded C2/config relationships.
- Wayback emits `web_archive_observation` and never maliciousness by itself.

- [ ] **Step 1: Add failing fixtures for all four providers**

Include legitimate no-result and malformed payload cases. Prove a JA3/similarity hit remains supporting context rather than direct attribution.

- [ ] **Step 2: Implement adapters with fixed hosts and strict parsers**

No sample submission in this task. MWDB remains lookup-only. Wayback results are capped and timestamped.

- [ ] **Step 3: Register safe workflows**

Only passive point-lookup capabilities enter baseline workflows. Similarity/search operations stay explicit graph/search mode.

- [ ] **Step 4: Run and commit**

```bash
node --test test/sslbl.test.js test/yaraify.test.js test/mwdb.test.js test/wayback-cdx.test.js
git add src/providers/sslbl.js src/providers/yaraify.js src/providers/mwdb.js src/providers/wayback-cdx.js src/providers/index.js config/providers.json src/workflows.js test/sslbl.test.js test/yaraify.test.js test/mwdb.test.js test/wayback-cdx.test.js
git commit -m "feat: add malware graph and historical web intelligence"
```

---

### Task 11: Defensive Knowledge and Crypto/Secret Context

**Files:**
- Create: `src/providers/d3fend.js`
- Create: `src/providers/chainabuse.js`
- Create: `src/providers/gitguardian-hmsl.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Modify: `src/workflows.js`
- Test: `test/d3fend.test.js`
- Test: `test/chainabuse.test.js`
- Test: `test/gitguardian-hmsl.test.js`

**Interfaces:**
- D3FEND supports `attack` and emits `defensive_knowledge` role `knowledge_only`.
- Chainabuse supports `crypto-address` and optionally URL/domain pivots where documented.
- GitGuardian accepts only `secret-fingerprint`, never raw secret strings.

- [ ] **Step 1: Write RED tests for semantic isolation and privacy**

Prove D3FEND cannot alter threat confidence; Chainabuse reports remain source claims; HMSL rejects raw secret-shaped inputs before network execution and redacts fingerprint values from verbose logs if logging policy requires it.

- [ ] **Step 2: Implement adapters**

Keep knowledge and secret-exposure calls outside ordinary fan-out unless explicitly allowed by safe policy.

- [ ] **Step 3: Run and commit**

```bash
node --test test/d3fend.test.js test/chainabuse.test.js test/gitguardian-hmsl.test.js test/intelligence-semantics.test.js
git add src/providers/d3fend.js src/providers/chainabuse.js src/providers/gitguardian-hmsl.js src/providers/index.js config/providers.json src/workflows.js test/d3fend.test.js test/chainabuse.test.js test/gitguardian-hmsl.test.js
git commit -m "feat: add knowledge crypto and secret context"
```

---

### Task 12: Owned-Asset Monitoring Lane

**Files:**
- Create: `src/providers/shadowserver.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Modify: `src/app.js`
- Test: `test/owned-asset-policy.test.js`
- Test: `test/shadowserver.test.js`

**Interfaces:**
- Shadowserver mode is `monitor`, sensitivity `owned_asset`, authorization `owned_network`, `fanoutEligible: false`.
- Asset queries must be wholly contained in server-approved CIDR/domain scope.

- [ ] **Step 1: Write policy RED tests**

Prove ordinary enrich cannot execute the adapter, unowned scopes fail closed, and a subset CIDR of an approved network is allowed.

- [ ] **Step 2: Implement passive/query-only adapter**

No network scan initiation. Normalize observations into contextual/exposure semantics without manufacturing malicious verdicts.

- [ ] **Step 3: Run and commit**

```bash
node --test test/owned-asset-policy.test.js test/shadowserver.test.js
git add src/providers/shadowserver.js src/providers/index.js config/providers.json src/app.js test/owned-asset-policy.test.js test/shadowserver.test.js
git commit -m "feat: add owned asset intelligence lane"
```

---

### Task 13: Sensitive Identity/Exposure Lane

**Files:**
- Create: `src/providers/hibp.js`
- Create: `src/providers/hudson-rock.js`
- Create: `src/providers/spycloud.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Modify: `src/app.js`
- Test: `test/sensitive-exposure-policy.test.js`
- Test: `test/sensitive-exposure-providers.test.js`

**Interfaces:**
- All three are `mode: 'sensitive'`, `fanoutEligible: false`.
- HIBP/Hudson Rock domain-scoped operations require verified-domain authorization where required by source semantics; account-level queries require explicit case context.
- Negative result remains `no_result`, never `safe`.

- [ ] **Step 1: Write authorization and retention RED tests**

Prove ordinary enrich and public MCP requests cannot trigger these providers; sensitive evidence is not emitted into shareable STIX/report outputs unless distribution policy permits a derived summary.

- [ ] **Step 2: Implement adapters behind the central policy gate**

Adapters themselves do not invent authorization; they receive only already-approved execution context.

- [ ] **Step 3: Run and commit**

```bash
node --test test/sensitive-exposure-policy.test.js test/sensitive-exposure-providers.test.js test/distribution-policy.test.js
git add src/providers/hibp.js src/providers/hudson-rock.js src/providers/spycloud.js src/providers/index.js config/providers.json src/app.js test/sensitive-exposure-policy.test.js test/sensitive-exposure-providers.test.js
git commit -m "feat: add sensitive exposure intelligence lane"
```

---

### Task 14: Infrastructure History and Anonymization Context

**Files:**
- Create: `src/providers/dnsdb.js`
- Create: `src/providers/validin.js`
- Create: `src/providers/spur.js`
- Create: `src/providers/netify.js`
- Create: `src/providers/team-cymru.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Test: `test/infrastructure-history-providers.test.js`

**Interfaces:**
- DNSDB/Validin emit `passive_dns_history` / `domain_ownership_history` where actually supported.
- Spur emits `anonymization_infrastructure` contextual evidence.
- Netify emits application/network identity context.
- Team Cymru remains explicit graph/search unless entitlement and cost benchmarks justify automatic use.

- [ ] **Step 1: Write common-contract RED fixtures**

Each provider fixture must prove first/last seen preservation, historical relationship timestamps where available, bounded pagination, no-result semantics, and explicit entitlement failure.

- [ ] **Step 2: Implement adapters and provider-family metadata**

Overlapping historical-DNS providers do not all enter default workflow. Mark one preferred candidate only after benchmark data exists; until then keep them explicit/search/graph.

- [ ] **Step 3: Run and commit**

```bash
node --test test/infrastructure-history-providers.test.js
git add src/providers/dnsdb.js src/providers/validin.js src/providers/spur.js src/providers/netify.js src/providers/team-cymru.js src/providers/index.js config/providers.json test/infrastructure-history-providers.test.js
git commit -m "feat: add infrastructure history capability family"
```

---

### Task 15: Enterprise Threat Intelligence Adapters

**Files:**
- Create: `src/providers/microsoft-ti.js`
- Create: `src/providers/recorded-future.js`
- Create: `src/providers/google-ti.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Test: `test/enterprise-ti-providers.test.js`

**Interfaces:**
- Missing credentials/tenant configuration => `unconfigured`.
- Provider methods expose only documented read-only/search/graph functions appropriate to configured entitlement.
- Microsoft tenant-backed capability requires tenant authorization context.

- [ ] **Step 1: Write RED tests for unconfigured and mocked configured behavior**

Fixtures cover representative actor/profile/indicator/PDNS relationships without asserting undocumented fields.

- [ ] **Step 2: Implement adapters with narrow documented surfaces**

Do not make generic arbitrary Graph/API proxy helpers. Endpoints remain fixed and operation names are enumerated.

- [ ] **Step 3: Run and commit**

```bash
node --test test/enterprise-ti-providers.test.js test/provider-capability-policy.test.js
git add src/providers/microsoft-ti.js src/providers/recorded-future.js src/providers/google-ti.js src/providers/index.js config/providers.json test/enterprise-ti-providers.test.js
git commit -m "feat: add enterprise threat intelligence adapters"
```

---

### Task 16: Underground Intelligence Provider Family

**Files:**
- Create: `src/providers/darkweb-family.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Test: `test/darkweb-provider-family.test.js`

**Interfaces:**
- Common normalized operations: `search`, `actor_context`, `exposure_context`, `marketplace_context`, `ransomware_context` only where backend supports them.
- Backends: Flashpoint, Flare, DarkOwl, Intel 471 are selected from server-side configuration; caller cannot choose arbitrary base URLs.
- All operations are explicit, non-fanout, restricted retention/distribution according to vendor terms.

- [ ] **Step 1: Write RED tests for provider-family substitution**

Mock at least two backend schemas and assert they normalize into the same evidence contract while preserving source provider identity.

- [ ] **Step 2: Implement backend dispatcher with fixed host maps**

Each backend gets an enumerated endpoint builder and parser. Unsupported operation for a backend returns a policy/operation error, not an invented no-result.

- [ ] **Step 3: Run and commit**

```bash
node --test test/darkweb-provider-family.test.js test/distribution-policy.test.js
git add src/providers/darkweb-family.js src/providers/index.js config/providers.json test/darkweb-provider-family.test.js
git commit -m "feat: add underground intelligence provider family"
```

---

### Task 17: Provider Value Benchmark and Admission Gate

**Files:**
- Create: `scripts/benchmark-providers.mjs`
- Create: `config/benchmark-corpus.example.json`
- Create: `src/core/provider-admission.js`
- Test: `test/provider-admission.test.js`

**Interfaces:**
- Benchmark output contains unique facts, unique graph edges, p50/p95 latency, error rate, no-result rate, decision-changing observations, and material unique observations per call.
- `admitToAutomaticWorkflow(metrics, thresholds)` is deterministic and offline; it never executes providers itself.

- [ ] **Step 1: Write RED tests for admission decisions**

A duplicative provider with zero unique facts must fail default admission even if reliable. A slower provider with high unique graph yield may pass graph-mode admission but not baseline fanout.

- [ ] **Step 2: Implement benchmark schema and admission helper**

The script reads a local corpus and calls existing authenticated gateway/provider operations; no credentials are stored in corpus files.

- [ ] **Step 3: Run and commit**

```bash
node --test test/provider-admission.test.js
git add scripts/benchmark-providers.mjs config/benchmark-corpus.example.json src/core/provider-admission.js test/provider-admission.test.js
git commit -m "feat: add provider value admission benchmark"
```

---

### Task 18: E2E, Documentation, and Release Gates

**Files:**
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: relevant MCP/plugin docs
- Create: `test/intelligence-fabric-e2e.test.mjs`
- Modify: CI verification scripts only if existing gates do not already include new files/tests.

**Interfaces:**
- E2E validates representative public enrichment, graph pivot, supply-chain, knowledge, sensitive-denied, owned-asset-denied, unconfigured enterprise, MCP intelligence, STIX distribution, and investigation/report compatibility.

- [ ] **Step 1: Write E2E test before documentation edits**

Use mocked upstreams where credentials are not available. Include one representative path for each execution mode and prove baseline `enrich` output shape remains compatible.

- [ ] **Step 2: Run full Node suite**

Run: `npm test`
Expected: PASS.

- [ ] **Step 3: Run repository gates**

Run: `npm run check`
Expected: PASS.

- [ ] **Step 4: Run provider/MCP/security-specific verification**

Run existing MAXX/provider invariant, MCP conformance, Maltego, PowerShell, secret-safety, and governance commands invoked by CI. Any command not already covered by `npm run check` must be recorded in the PR body with its output summary.

- [ ] **Step 5: Update documentation**

Document observable types, execution modes, policy boundaries, provider status semantics, new intelligence operations, configuration variables, and which provider capabilities are passive vs explicit.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/ARCHITECTURE.md test/intelligence-fabric-e2e.test.mjs
git commit -m "docs: finalize intelligence fabric integration"
```

- [ ] **Step 7: Open/update protected PR and verify CI**

Confirm Tooling smoke and CodeQL succeed on the exact head SHA. Review the complete diff for credential leakage, unexpected egress hosts, unrestricted pagination, and accidental default-workflow expansion.

- [ ] **Step 8: Merge only through protected PR flow**

Do not move `main` directly. After merge, verify the Vercel production deployment SHA equals the merged commit.

- [ ] **Step 9: Production smoke**

Retest: health/meta, fast IP enrichment, standard domain enrichment, VT graph pivot, urlscan deep pivot, package/deps path, knowledge path, explicit-denial sensitive request, MCP capabilities, and one investigation lifecycle. Check Vercel logs for new 4xx/5xx and provider runtime-health regressions.

---

## Dependency Order

Tasks 1–6 are Wave 0 and form the mandatory fabric foundation.

Tasks 7–8 are Wave 1 and deepen existing providers.

Tasks 9–11 are Wave 2 and add high-value low-friction evidence classes.

Tasks 12–13 are Wave 3 and add owned-asset/sensitive lanes only after policy enforcement exists.

Tasks 14–16 are Waves 4–5 and add optional commercial/provider-family integrations.

Task 17 may begin after Task 6 but becomes most useful after Tasks 7–16 have candidates to compare.

Task 18 is the final integration/release gate and also runs at the end of each shippable wave before merging that wave if implementation is split into multiple PRs.

## Recommended PR Strategy

Use multiple protected PRs rather than one enormous final PR:

1. PR A — Tasks 1–6: fabric primitives and normalized intelligence surface.
2. PR B — Tasks 7–8: VT/urlscan/Censys deep pivots.
3. PR C — Tasks 9–11: exploit, supply-chain, TLS/malware, historical-web, knowledge, crypto/secret context.
4. PR D — Tasks 12–13: owned-asset and sensitive lanes.
5. PR E — Tasks 14–16: infrastructure-history, enterprise, and underground-provider families.
6. PR F — Task 17 plus final cross-wave benchmark/admission tuning if not landed earlier.

Every PR independently runs Task 18 release gates appropriate to its changed surface. This keeps rollback and review sane and prevents an upstream vendor outage from blocking unrelated capabilities.

## Self-Review Results

- Spec coverage: every approved design section maps to at least one task.
- Placeholder scan: no implementation step depends on TBD/TODO placeholders; commercial adapters explicitly remain unconfigured when credentials are absent.
- Type consistency: observable names, mode enums, authorization enums, distribution source, planner signature, and evidence policy fields are consistent across tasks.
- Backward compatibility: existing `enrich` remains phase-1 only by default; secondary pivots are opt-in through the intelligence surface until intentionally promoted by provider-admission metrics.
- Security boundary: sensitive/monitor/analysis capabilities cannot become fanout-eligible under the provider-policy validator.

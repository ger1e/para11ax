<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md) and the current README.

# PARA11AX Intelligence Fabric Gap-Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four implementation gaps found during self-review of the primary intelligence-fabric plan: username/User Scanner integration, DomainTools/WhoisXML historical-domain capability, richer Spamhaus/IBM X-Force enterprise capability, and explicit provider-cap invariant coverage.

**Architecture:** This companion plan extends `docs/superpowers/plans/2026-09-13-intelligence-fabric-implementation-plan.md`; it does not replace it. All tasks depend on the Wave 0 policy/authorization/intelligence surface from Tasks 1–6 of the primary plan and use the same provider registry, fixed-host egress, Evidence v2 normalization, and authorization policy.

**Tech Stack:** Node.js 24.x ESM, built-in `node:test`, existing User Scanner worker/router, JSON provider manifest, Vercel/MCP.

**Spec:** `docs/superpowers/specs/2026-09-13-intelligence-fabric-design.md`

## Global Constraints

- No username scan is automatically triggered by ordinary enrichment.
- Domain-history vendors remain explicit graph/search alternatives until benchmarked.
- Commercial enterprise providers remain unconfigured when credentials are absent.
- No arbitrary vendor URL or caller-selected host is accepted.
- Provider-count bounds remain explicit and test-covered; do not silently remove the bound.

---

### Task G1: Wire `username` to the Existing User Scanner Lane

**Files:**
- Modify: `src/user-scanner.js`
- Modify: `src/app.js`
- Modify: `src/mcp/server.js`
- Test: `test/intelligence-username-lane.test.js`

**Interfaces:**
- Consumes canonical `{ type: 'username', value }` from Task 2 of the primary plan.
- Produces the same bounded User Scanner result currently exposed by `para11ax_user_scan`, wrapped as intelligence evidence/relationships where appropriate.
- Mode is explicit `search`; `fanoutEligible` is false.

- [ ] **Step 1: Write the failing lane test**

```js
import test from 'node:test';
import assert from 'node:assert/strict';

test('username intelligence operation delegates to bounded User Scanner and never enrich fanout', async () => {
  const result = await runIntelligence({ operation: 'search', indicator: 'user:para11ax_qa_fixture' });
  assert.equal(result.type, 'username');
  assert.equal(result.operation, 'search');
  assert.equal(result.policy.fanoutEligible, false);
});
```

Also assert an ordinary `handleEnrich` request for the same canonical username is rejected or has no automatic workflow, according to the final Wave 0 routing contract.

- [ ] **Step 2: Run and verify RED**

Run: `node --test test/intelligence-username-lane.test.js`
Expected: FAIL because the normalized intelligence operation is not wired to User Scanner yet.

- [ ] **Step 3: Add a narrow adapter function around existing User Scanner behavior**

Reuse the existing scanner implementation; do not duplicate site modules or create another scanner. Convert only stable outputs (`found`, `notFound`, `errors`, bounded site observations) into normalized evidence and relationships.

- [ ] **Step 4: Keep existing `para11ax_user_scan` backward compatible**

The dedicated tool remains available. The new intelligence surface delegates to the same bounded core path.

- [ ] **Step 5: Run and commit**

```bash
node --test test/intelligence-username-lane.test.js test/user-scanner*.test.js test/mcp*.test.js
git add src/user-scanner.js src/app.js src/mcp/server.js test/intelligence-username-lane.test.js
git commit -m "feat: integrate username intelligence lane"
```

---

### Task G2: DomainTools and WhoisXML Historical-Domain Alternatives

**Files:**
- Create: `src/providers/domaintools.js`
- Create: `src/providers/whoisxml.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Test: `test/domain-history-provider-family.test.js`

**Interfaces:**
- Both providers are explicit `graph`/`search` capability sources, not baseline fanout.
- They emit only semantics actually supported by the response: `passive_dns_history`, `domain_ownership_history`, registration/network context, and relationships with first/last-seen metadata when available.
- They compete with DNSDB/Validin in provider-admission benchmarking rather than all entering automatic workflows.

- [ ] **Step 1: Write failing provider-family fixtures**

Mock representative historical WHOIS and DNS responses for each vendor. Assert identical normalized relationship types where the semantics match, while provider provenance remains distinct.

- [ ] **Step 2: Verify RED**

Run: `node --test test/domain-history-provider-family.test.js`
Expected: module/adapter registration failure.

- [ ] **Step 3: Implement fixed-host documented adapters**

Each adapter enumerates allowed operations; no generic arbitrary endpoint proxy is permitted. Bound pages and relationship counts using policy metadata.

- [ ] **Step 4: Register as explicit alternatives**

Set `fanoutEligible: false` and a shared `providerFamily` such as `domain-history` for benchmark comparison.

- [ ] **Step 5: Run and commit**

```bash
node --test test/domain-history-provider-family.test.js test/provider-capability-policy.test.js
git add src/providers/domaintools.js src/providers/whoisxml.js src/providers/index.js config/providers.json test/domain-history-provider-family.test.js
git commit -m "feat: add domain history provider alternatives"
```

---

### Task G3: Rich Spamhaus and IBM X-Force Enterprise Capabilities

**Files:**
- Create: `src/providers/spamhaus-intel.js`
- Create: `src/providers/ibm-xforce.js`
- Modify: `src/providers/index.js`
- Modify: `config/providers.json`
- Test: `test/enterprise-ti-secondary-providers.test.js`

**Interfaces:**
- `spamhaus-intel` is distinct from existing public `spamhaus-drop`; the latter remains unchanged.
- `ibm-xforce` is optional credentialed enterprise CTI.
- Missing credentials => unconfigured. Both remain bounded read-only/search/graph capabilities.

- [ ] **Step 1: Write failing fixtures**

Cover IP/domain/malware context only where documented by the selected API surfaces. Include 401/403 entitlement failure, rate limiting, malformed payload, and no-result semantics.

- [ ] **Step 2: Implement Spamhaus intelligence adapter**

Do not modify `spamhaus-drop.js` semantics. Use a separate provider name and credential field so public DROP data and paid intelligence cannot be confused in provenance or distribution rules.

- [ ] **Step 3: Implement IBM X-Force adapter**

Enumerate supported indicator lookups and graph/search operations; fixed hosts only, no arbitrary API-path passthrough.

- [ ] **Step 4: Run and commit**

```bash
node --test test/enterprise-ti-secondary-providers.test.js test/provider-capability-policy.test.js
git add src/providers/spamhaus-intel.js src/providers/ibm-xforce.js src/providers/index.js config/providers.json test/enterprise-ti-secondary-providers.test.js
git commit -m "feat: add secondary enterprise intelligence providers"
```

---

### Task G4: Provider-Cap Invariant and Family-Aware Counting

**Files:**
- Modify: `src/providers/manifest.js`
- Modify: `src/providers/index.js` only if provider-family representation changes physical adapter count.
- Test: `test/provider-count-bound.test.js`

**Interfaces:**
- Preserve a hard finite upper bound on registered physical adapters.
- Provider-native methods and backend families should not consume separate automatic-provider slots when they can live behind one adapter safely.

- [ ] **Step 1: Write the failing invariant test before changing the cap**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { ALL_PROVIDERS } from '../src/providers/index.js';

test('provider registry remains explicitly bounded after intelligence expansion', () => {
  assert.ok(ALL_PROVIDERS.length <= 96);
});
```

Also assert provider names are unique and provider-family members expose deterministic family metadata.

- [ ] **Step 2: Count projected physical adapters after all primary-plan and gap-plan tasks**

If the count is `<= 64`, retain `MAX_PROVIDERS = 64`. If it exceeds 64 only because legitimately distinct fixed-host adapters are required, increase the constant to the smallest reviewed bound that covers the projected set, with `96` as the maximum allowed by this plan. Do not remove the bound or set an arbitrary huge number.

- [ ] **Step 3: Prefer capability methods/provider families before increasing the cap**

Ensure VT/urlscan/Censys sub-capabilities and dark-web backend operations do not each become separate entries in `ALL_PROVIDERS` unless fixed-host/auth/provenance requirements truly require a distinct adapter.

- [ ] **Step 4: Run and commit**

```bash
node --test test/provider-count-bound.test.js test/provider-manifest*.test.js test/provider-contract*.test.js
git add src/providers/manifest.js src/providers/index.js test/provider-count-bound.test.js
git commit -m "test: bound expanded provider registry"
```

---

## Dependency Placement

- G1 executes immediately after primary Task 6.
- G2 executes alongside primary Task 14 before provider benchmarking/admission.
- G3 executes alongside primary Task 15.
- G4 runs after all planned provider registrations are represented, before final Task 18 release gates.

## Self-Review Results

- Username/User Scanner reuse is now explicitly implemented rather than merely adding a new observable.
- DomainTools and WhoisXML are represented as historical-domain alternatives without forcing duplicate automatic fanout.
- Rich Spamhaus and IBM X-Force are represented separately from existing public providers and remain optional/unconfigured without credentials.
- Provider-count strategy now has an explicit red/green invariant and a reviewed finite ceiling.
- No new task relaxes the fixed-host, read-only-by-default, authorization, distribution, or Evidence v2 requirements from the approved spec.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

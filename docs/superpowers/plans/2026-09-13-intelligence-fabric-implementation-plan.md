<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. This implementation plan is preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md) and the current README.

# Intelligence Fabric Implementation Plan

> **For agentic workers:** Implement each task through RED → GREEN → exact-head verification. Do not widen provider surfaces merely to match an upstream API.

**Goal:** Deliver a bounded provenance-first intelligence fabric using public, nonprofit, community, free or low-friction sources and already-established gateway integrations. Paid-only provider expansion is out of scope.

**Architecture:** Keep baseline enrichment backward-compatible. Add secondary capabilities through explicit modes, central authorization, fixed-host adapters, bounded relationship expansion, deterministic evidence normalization, and distribution/retention policy.

**Tech Stack:** Node.js 24.x ESM, built-in `node:test`, Vercel Functions, GitHub Actions, existing PARA11AX provider/evidence contracts.

## Global Constraints

- Baseline `enrich` remains phase one and is the only automatic fanout mode.
- Secondary modes are `graph`, `search`, `monitor`, `analysis`, and `knowledge`.
- Caller input never chooses arbitrary provider URLs, methods, trust flags, or credentials.
- Provider requests use fixed destinations and bounded response sizes.
- Pagination is bounded and opt-in; first-page-only is preferred.
- Provider failures remain failures and never become absence or negative evidence.
- `no_result` never means safe.
- Sensitive/no-store evidence never enters shared caches or shareable exports unless a separate derived-summary policy explicitly permits it.
- Owned-network access is bound to the canonical subject and server-controlled scope.
- New paid-only integrations are not implementation targets.

---

## Completed Foundation

### Tasks 1–6: Fabric primitives and normalized intelligence surface

Implemented capability policy, intelligence-only observables, trusted authorization context, semantic/distribution enforcement, bounded phase-two planning/execution, normalized HTTP/MCP/CLI intelligence operations, and isolated username search.

### Tasks 7–8: Deep pivots for established providers

Implemented bounded explicit graph/search/history surfaces while preserving existing point enrichment and preventing default-fanout expansion.

### Task 9: Exploit and supply-chain context

Implemented bounded exploit-maturity and dependency-relationship capabilities with truthful no-result semantics.

### Task 10: TLS, malware, and historical-web context

Implemented passive/read-only TLS-malware, malware-similarity, malware-configuration, and historical-web capabilities. No sample submission, rescanning, or active upstream operation was introduced.

### Task 11: Defensive knowledge, crypto abuse, and secret context

Implemented defensive-technique knowledge, crypto-abuse screening, and privacy-preserving secret-fingerprint checks. Raw-secret-shaped input is rejected before egress.

### Task 12: Owned-network monitoring

Implemented a bounded owned-asset reporting lane. Trusted deployment CIDR/domain scope is matched against the canonical subject before execution, and public callers cannot inject ownership claims.

### Task 13: Free network identity context

Implemented a bounded explicit IP-to-ASN/network registry capability with no credential requirement. It remains graph-only and non-fanout.

---

## Task 14: Provider Value Benchmark and Admission Gate

**Files:**
- Create: `scripts/benchmark-providers.mjs`
- Create: `config/benchmark-corpus.example.json`
- Create: `src/core/provider-admission.js`
- Test: `test/provider-admission.test.js`

**Interfaces:**
- Benchmark output contains unique facts, unique graph edges, p50/p95 latency, error rate, no-result rate, decision-changing observations, and material unique observations per call.
- `admitToAutomaticWorkflow(metrics, thresholds)` is deterministic and offline; it never executes providers itself.

**Step 1: Write RED tests for admission decisions**

A duplicative provider with zero unique facts must fail default admission even if reliable. A slower provider with high unique graph yield may pass graph-mode admission but not baseline fanout.

**Step 2: Implement benchmark schema and admission helper**

The script reads a local corpus and calls existing authenticated gateway/provider operations; no credentials are stored in corpus files.

**Step 3: Verify**

```bash
node --test test/provider-admission.test.js
npm run check
```

---

## Task 15: E2E, Documentation, and Release Gates

**Files:**
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: relevant MCP/plugin docs
- Create: `test/intelligence-fabric-e2e.test.mjs`
- Modify CI verification only if existing gates do not already cover the changed surface.

**Step 1: Write E2E before documentation edits**

Use mocked upstreams where credentials are unavailable. Cover representative public enrichment, graph pivot, supply-chain, knowledge, owned-asset denial, free network identity, MCP intelligence, STIX distribution, and investigation/report compatibility. Prove baseline `enrich` output remains compatible.

**Step 2: Run full Node suite**

```bash
npm test
```

**Step 3: Run repository gates**

```bash
npm run check
```

**Step 4: Run provider/MCP/security verification**

Run MAXX/provider invariants, MCP conformance, Maltego, PowerShell, secret-safety, governance, and CodeQL gates. Record any gate not already covered by `npm run check` in the PR body.

**Step 5: Update documentation**

Document observable types, execution modes, policy boundaries, provider status semantics, configuration variables, and passive versus explicit capabilities.

**Step 6: Protected PR verification**

Confirm Tooling smoke and CodeQL succeed on the exact head SHA. Review the complete diff for credential leakage, unexpected egress hosts, unrestricted pagination, and accidental default-workflow expansion.

**Step 7: Merge and production verification**

Merge only through protected PR flow. After merge, verify the production deployment SHA equals the merged commit and run health/meta, representative enrichment, graph, package, knowledge, owned-asset denial, MCP, and investigation lifecycle smoke tests.

## Dependency Order

Tasks 1–6 form the mandatory fabric foundation. Tasks 7–13 add bounded evidence classes and explicit capabilities. Task 14 controls future admission based on measured value. Task 15 is the final integration and release gate.

## PR Strategy

Keep provider-wave changes independently reviewable where practical. Every shippable wave must pass deterministic repository checks and security analysis before promotion. The final PR must remain mergeable without bypassing protected-main controls.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

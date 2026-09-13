<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md) and the current README.

# MAX Intelligence Enrichment Sub-Atomic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Each task is independently testable, reviewable, and committable. Do not batch adjacent tasks merely because they touch the same file.

**Goal:** Re-express the original MAX Intelligence Enrichment plan as sub-atomic RED→GREEN work units for evidence-quality scoring, infrastructure-context correlation, sanitized provider telemetry, Modat safety, contract verification, CI, and production verification.

**Architecture:** Preserve the existing correlation, telemetry, scheduler, provider-runner, normalization, status, and deployment architecture. Each task adds exactly one behavior or one verification surface. Infrastructure context remains semantically separate from threat polarity, telemetry remains aggregate-only, and Modat remains neutral infrastructure context.

**Tech Stack:** Node.js 24.x ESM, built-in `node:test`, Vercel Functions, GitHub Actions, existing PARA11AX provider/evidence contracts.

**Spec:** `docs/superpowers/specs/2026-08-22-max-intelligence-enrichment.md`

**Supersedes for execution:** `docs/superpowers/plans/2026-08-22-max-intelligence-enrichment.md` remains a historical plan. This file is the executable replacement.

## Global Constraints

- Preserve `/api/para11ax/enrich`, `/api/para11ax/batch`, `/api/para11ax/stix`, `/api/para11ax/meta`, `/api/para11ax/health`, and `/api/para11ax/status` contracts.
- No new framework, database, queue, cache service, or client-side vendor credential.
- Evidence quality measures support quality, never maliciousness.
- Infrastructure observations never become reputation votes without independent threat evidence.
- Default telemetry contains no raw indicators, credentials, authorization headers, query strings, response bodies, or provider secrets.
- Scheduler concurrency remains `<= 4`; request deadline remains `20 seconds`.
- All collections and output surfaces remain bounded and deterministically ordered.
- Provider failures stay failures; they never become absence or negative intelligence.
- Modat remains fixed-host, server-authenticated, bounded, fail-closed, and neutral-context only.

---

### Task A1: Evidence Quality Object Skeleton

**Files:**
- Modify: `src/core/correlate.js`
- Test: `test/correlation-evidence-quality.test.js`

**Interfaces:**
- Consumes normalized `evidence[]` and existing correlation input.
- Produces `correlation.evidenceQuality` with only `normalizedEvidenceCount` in this task.

- [ ] **Step 1: Write the failing test**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { correlate } from '../src/core/correlate.js';

test('evidence quality reports normalized evidence count independently of verdict', () => {
  const result = correlate({
    indicator: '203.0.113.10',
    type: 'ip',
    evidence: [
      { provider: 'a', observation: { kind: 'network_identity', verdict: 'observed' }, relationships: [] },
      { provider: 'b', observation: { kind: 'reputation', verdict: 'malicious' }, relationships: [] },
    ],
    failures: [],
  });
  assert.equal(result.evidenceQuality.normalizedEvidenceCount, 2);
});
```

- [ ] **Step 2: Run and verify RED**

Run: `node --test test/correlation-evidence-quality.test.js`
Expected: FAIL because `evidenceQuality` does not yet exist.

- [ ] **Step 3: Implement only the count field**

Add a bounded `evidenceQuality` object to the existing correlation result. Do not add level, freshness, diversity, or contradiction fields yet.

- [ ] **Step 4: Run and verify GREEN**

Run: `node --test test/correlation-evidence-quality.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/correlate.js test/correlation-evidence-quality.test.js
git commit -m "feat(correlation): add evidence quality count"
```

---

### Task A2: Evidence Provider Diversity

**Files:**
- Modify: `src/core/correlate.js`
- Modify: `test/correlation-evidence-quality.test.js`

**Interfaces:**
- Extends `evidenceQuality` with `providerCount` and sorted unique `providers`.

- [ ] **Step 1: Add a failing test**

```js
test('evidence quality deduplicates and sorts providers', () => {
  const result = correlate({
    indicator: '203.0.113.10', type: 'ip', failures: [],
    evidence: [
      { provider: 'zeta', observation: { kind: 'network_identity', verdict: 'observed' }, relationships: [] },
      { provider: 'alpha', observation: { kind: 'routing', verdict: 'observed' }, relationships: [] },
      { provider: 'zeta', observation: { kind: 'registration', verdict: 'observed' }, relationships: [] },
    ],
  });
  assert.deepEqual(result.evidenceQuality.providers, ['alpha', 'zeta']);
  assert.equal(result.evidenceQuality.providerCount, 2);
});
```

- [ ] **Step 2: Run and verify RED**

Run: `node --test test/correlation-evidence-quality.test.js`
Expected: FAIL on missing provider fields.

- [ ] **Step 3: Implement unique sorted provider aggregation**

Use a bounded `Set` derived only from normalized evidence provider names. Provider execution failures are not included.

- [ ] **Step 4: Verify GREEN and commit**

```bash
node --test test/correlation-evidence-quality.test.js
git add src/core/correlate.js test/correlation-evidence-quality.test.js
git commit -m "feat(correlation): add evidence provider diversity"
```

---

### Task A3: Evidence Freshness Summary

**Files:**
- Modify: `src/core/correlate.js`
- Modify: `test/correlation-evidence-quality.test.js`

**Interfaces:**
- Extends `evidenceQuality` with `freshEvidenceCount`, `staleEvidenceCount`, and `unknownFreshnessCount`.
- Uses only normalized `retrievedAt` and/or already-normalized evidence timestamps; no provider-specific parsing.

- [ ] **Step 1: Add failing deterministic-time test**

Inject or use the existing correlation clock interface. Fixture evidence contains one recent timestamp, one older timestamp beyond the chosen freshness threshold already used elsewhere in the repository if one exists, and one null timestamp.

```js
assert.equal(result.evidenceQuality.freshEvidenceCount, 1);
assert.equal(result.evidenceQuality.staleEvidenceCount, 1);
assert.equal(result.evidenceQuality.unknownFreshnessCount, 1);
```

- [ ] **Step 2: Run and verify RED**

Run: `node --test test/correlation-evidence-quality.test.js`
Expected: FAIL on missing freshness fields.

- [ ] **Step 3: Implement bounded freshness categorization**

Prefer an existing shared freshness helper if present. If no shared threshold exists, define one named constant in `correlate.js` and cover it directly in the test. Invalid timestamps count as unknown, never stale.

- [ ] **Step 4: Verify GREEN and commit**

```bash
node --test test/correlation-evidence-quality.test.js
git add src/core/correlate.js test/correlation-evidence-quality.test.js
git commit -m "feat(correlation): summarize evidence freshness"
```

---

### Task A4: Contradiction Count in Quality

**Files:**
- Modify: `src/core/correlate.js`
- Modify: `test/correlation-evidence-quality.test.js`

**Interfaces:**
- Reuses the existing contradiction output.
- Adds `evidenceQuality.contradictionCount` only.

- [ ] **Step 1: Add failing test using existing positive/negative contradiction fixtures**

```js
assert.equal(result.evidenceQuality.contradictionCount, result.contradictions.length);
```

- [ ] **Step 2: Verify RED**

Run: `node --test test/correlation-evidence-quality.test.js`
Expected: FAIL because the quality object does not expose contradiction count.

- [ ] **Step 3: Implement by referencing existing contradiction results**

Do not recompute threat polarity in a second code path.

- [ ] **Step 4: Verify GREEN and commit**

```bash
node --test test/correlation-evidence-quality.test.js test/correlation.test.js
git add src/core/correlate.js test/correlation-evidence-quality.test.js
git commit -m "feat(correlation): include contradiction count in quality"
```

---

### Task A5: Deterministic Evidence Quality Level

**Files:**
- Modify: `src/core/correlate.js`
- Modify: `test/correlation-evidence-quality.test.js`

**Interfaces:**
- Adds `evidenceQuality.level` with a closed enum such as `insufficient | limited | moderate | strong`.
- Level depends on support quality only, never verdict polarity.

- [ ] **Step 1: Add failing polarity-independence test**

Build two correlation inputs with identical evidence counts/providers/freshness/contradictions but opposite threat verdicts. Assert equal `evidenceQuality.level`.

```js
assert.equal(malicious.evidenceQuality.level, benign.evidenceQuality.level);
```

- [ ] **Step 2: Add failing boundary tests**

Cover each quality level with exact fixture counts so the thresholds are executable documentation.

- [ ] **Step 3: Verify RED**

Run: `node --test test/correlation-evidence-quality.test.js`
Expected: FAIL on missing `level`.

- [ ] **Step 4: Implement one deterministic scoring function**

Keep the function local to `correlate.js` unless repository style already has a scoring helper. Inputs are only normalized evidence count, provider count, freshness counts, and contradiction count.

- [ ] **Step 5: Verify GREEN and commit**

```bash
node --test test/correlation-evidence-quality.test.js test/correlation.test.js
git add src/core/correlate.js test/correlation-evidence-quality.test.js
git commit -m "feat(correlation): derive deterministic evidence quality level"
```

---

### Task A6: Infrastructure Provider Context

**Files:**
- Modify: `src/core/correlate.js`
- Test: `test/correlation-infrastructure-context.test.js`

**Interfaces:**
- Produces `correlation.infrastructureContext.providers` for network indicators.
- Only evidence whose semantic class is infrastructure/network context participates.

- [ ] **Step 1: Write failing test**

Use one infrastructure evidence item and one reputation item. Assert only the infrastructure provider appears.

```js
assert.deepEqual(result.infrastructureContext.providers, ['censys']);
```

- [ ] **Step 2: Verify RED**

Run: `node --test test/correlation-infrastructure-context.test.js`
Expected: FAIL on missing `infrastructureContext`.

- [ ] **Step 3: Implement infrastructure-provider collection**

Use existing semantic classification helpers rather than matching provider names.

- [ ] **Step 4: Verify GREEN and commit**

```bash
node --test test/correlation-infrastructure-context.test.js
git add src/core/correlate.js test/correlation-infrastructure-context.test.js
git commit -m "feat(correlation): add infrastructure provider context"
```

---

### Task A7: Shared Infrastructure Relationship Targets

**Files:**
- Modify: `src/core/correlate.js`
- Modify: `test/correlation-infrastructure-context.test.js`

**Interfaces:**
- Adds bounded `infrastructureContext.sharedTargets[]` entries shaped as `{ targetType, target, providers, providerCount }`.
- Only targets observed by at least two independent infrastructure-context providers are emitted.

- [ ] **Step 1: Add failing corroboration test**

Two infrastructure providers point to the same certificate/domain relationship; a third unrelated target appears once. Assert only the shared target is emitted.

- [ ] **Step 2: Add failing bound/order test**

Generate more candidate shared targets than the chosen repository-safe cap. Assert deterministic sorting and truncation.

- [ ] **Step 3: Verify RED**

Run: `node --test test/correlation-infrastructure-context.test.js`
Expected: FAIL on missing `sharedTargets`.

- [ ] **Step 4: Implement canonical target keying and provider dedupe**

Do not count duplicate edges from the same provider twice.

- [ ] **Step 5: Verify GREEN and commit**

```bash
node --test test/correlation-infrastructure-context.test.js
git add src/core/correlate.js test/correlation-infrastructure-context.test.js
git commit -m "feat(correlation): correlate shared infrastructure targets"
```

---

### Task A8: Infrastructure Context Must Not Affect Reputation

**Files:**
- Modify: `test/correlation-infrastructure-context.test.js`
- Production code: only if this RED test exposes a real bug.

**Interfaces:**
- Regression proof only.

- [ ] **Step 1: Write the regression test**

Create multiple agreeing infrastructure-context providers with no reputation evidence. Assert the threat/reputation corroboration count remains zero and malicious verdict is not created.

```js
assert.equal(result.reputation?.corroboratingProviders?.length ?? 0, 0);
assert.notEqual(result.verdict, 'malicious');
```

- [ ] **Step 2: Run test**

Run: `node --test test/correlation-infrastructure-context.test.js`
Expected: PASS if current semantics are correct. If it passes, record this as a characterization proof and make no production change. If it fails, treat that failure as RED and apply the smallest semantic fix.

- [ ] **Step 3: Commit the proof or minimal fix**

```bash
git add test/correlation-infrastructure-context.test.js src/core/correlate.js
git commit -m "test(correlation): prove infrastructure context stays neutral"
```

---

### Task A9: Telemetry Aggregate by Provider

**Files:**
- Modify: `src/core/telemetry.js`
- Test: `test/telemetry-provider-aggregate.test.js`

**Interfaces:**
- Extends `telemetry.stats()` with sorted `byProvider` counts.
- Does not change emitted event payloads.

- [ ] **Step 1: Write failing test**

Emit sanitized fixture events for providers `zeta`, `alpha`, `zeta`. Assert:

```js
assert.deepEqual(stats.byProvider, { alpha: 1, zeta: 2 });
```

- [ ] **Step 2: Verify RED**

Run: `node --test test/telemetry-provider-aggregate.test.js`
Expected: FAIL on missing `byProvider`.

- [ ] **Step 3: Implement bounded aggregate map**

Keys must come only from registered/sanitized provider identifiers already accepted by telemetry. Do not retain raw event bodies beyond existing behavior.

- [ ] **Step 4: Verify GREEN and commit**

```bash
node --test test/telemetry-provider-aggregate.test.js test/telemetry.test.js
git add src/core/telemetry.js test/telemetry-provider-aggregate.test.js
git commit -m "feat(telemetry): aggregate provider outcomes"
```

---

### Task A10: Telemetry Aggregate by Status

**Files:**
- Modify: `src/core/telemetry.js`
- Test: `test/telemetry-status-aggregate.test.js`

**Interfaces:**
- Extends `telemetry.stats()` with sorted `byStatus` counts.

- [ ] **Step 1: Write failing test**

Emit `success`, `timeout`, `failure`, `success`; assert exact counts and deterministic keys.

- [ ] **Step 2: Verify RED**

Run: `node --test test/telemetry-status-aggregate.test.js`
Expected: FAIL on missing `byStatus`.

- [ ] **Step 3: Implement status aggregation without changing provider aggregation**

Unknown status values must map to the existing sanitized fallback or be rejected consistently with current telemetry behavior.

- [ ] **Step 4: Verify GREEN and commit**

```bash
node --test test/telemetry-status-aggregate.test.js test/telemetry-provider-aggregate.test.js test/telemetry.test.js
git add src/core/telemetry.js test/telemetry-status-aggregate.test.js
git commit -m "feat(telemetry): aggregate status outcomes"
```

---

### Task A11: Telemetry Secret and Indicator Exclusion Proof

**Files:**
- Test: `test/telemetry-sanitization-regression.test.js`
- Production code: only if the proof fails.

**Interfaces:**
- Verifies stats and emitted events contain aggregates only.

- [ ] **Step 1: Write regression test with canary values**

Use unmistakable canaries such as `CANARY_SECRET_DO_NOT_LEAK` and `203.0.113.77`. Serialize event snapshots and `stats()` and assert neither canary appears.

```js
assert.equal(JSON.stringify(stats).includes('CANARY_SECRET_DO_NOT_LEAK'), false);
assert.equal(JSON.stringify(stats).includes('203.0.113.77'), false);
```

- [ ] **Step 2: Run test**

Run: `node --test test/telemetry-sanitization-regression.test.js`
Expected: PASS if the current sanitizer remains correct. If it fails, the failure becomes RED for the smallest sanitizer fix.

- [ ] **Step 3: Commit proof/minimal fix**

```bash
git add test/telemetry-sanitization-regression.test.js src/core/telemetry.js
git commit -m "test(telemetry): prove aggregate sanitization"
```

---

### Task A12: Authenticated Status Surfaces New Aggregates Only

**Files:**
- Test: `test/status-telemetry-aggregate.test.js`
- Modify: `src/app.js` only if existing pass-through does not expose the new aggregate fields.

**Interfaces:**
- `/api/para11ax/status` remains authenticated.
- Status output exposes aggregate telemetry from `telemetry.stats()` and no raw telemetry events.

- [ ] **Step 1: Write failing/characterization test**

Build an app with fixture telemetry stats containing `byProvider` and `byStatus`. Assert authenticated status includes those exact aggregate objects and an unauthenticated request remains `401`.

- [ ] **Step 2: Run focused test**

Run: `node --test test/status-telemetry-aggregate.test.js test/meta-status.test.js`
Expected: PASS if status already passes stats through; otherwise RED on missing aggregate fields.

- [ ] **Step 3: Apply minimal pass-through change only if required**

Do not add any raw event array to status.

- [ ] **Step 4: Verify and commit**

```bash
node --test test/status-telemetry-aggregate.test.js test/meta-status.test.js
git add test/status-telemetry-aggregate.test.js src/app.js
git commit -m "test(status): verify telemetry aggregate surface"
```

---

### Task A13: Modat Neutral-Verdict Regression

**Files:**
- Test: `test/modat-neutral-context.test.js`
- Modify: `src/providers/modat.js` only if regression is exposed.

**Interfaces:**
- Modat positive infrastructure observations normalize as neutral/observed context, never maliciousness.

- [ ] **Step 1: Write fixture-based regression test**

Mock a successful Magnify host/DNS response and assert normalized evidence kind is infrastructure/passive-DNS context and verdict is `observed` (or the exact existing neutral verdict), with no malicious verdict synthesized.

- [ ] **Step 2: Run test**

Run: `node --test test/modat-neutral-context.test.js test/modat-provider.test.js`
Expected: PASS if current adapter remains correct; otherwise RED for minimal fix.

- [ ] **Step 3: Commit proof/minimal fix**

```bash
git add test/modat-neutral-context.test.js src/providers/modat.js
git commit -m "test(modat): preserve neutral infrastructure semantics"
```

---

### Task A14: Modat Fixed-Host and Fail-Closed Regression

**Files:**
- Test: `test/modat-boundary-regression.test.js`
- Modify: `src/providers/modat.js` or shared egress only if a real regression is exposed.

**Interfaces:**
- Host remains `api.magnify.modat.io`.
- Redirect, malformed schema, oversized response, or non-success HTTP never becomes `not_found`/`clean`.

- [ ] **Step 1: Write four focused tests**

One test each for fixed host, malformed response, upstream HTTP failure, and redirect rejection according to existing transport contracts.

- [ ] **Step 2: Run and verify**

Run: `node --test test/modat-boundary-regression.test.js test/modat-provider.test.js`
Expected: PASS unless an actual boundary bug exists.

- [ ] **Step 3: Commit proof/minimal fix**

```bash
git add test/modat-boundary-regression.test.js src/providers/modat.js src/core/egress.js
git commit -m "test(modat): lock fixed-host fail-closed boundaries"
```

---

### Task A15: Targeted Contract Gate

**Files:** no production changes unless a concrete regression is found.

**Interfaces:**
- Consumes Tasks A1-A14.
- Produces one targeted green gate before the full repository suite.

- [ ] **Step 1: Run targeted suite**

```bash
node --test \
  test/correlation-evidence-quality.test.js \
  test/correlation-infrastructure-context.test.js \
  test/correlation.test.js \
  test/telemetry-provider-aggregate.test.js \
  test/telemetry-status-aggregate.test.js \
  test/telemetry-sanitization-regression.test.js \
  test/telemetry.test.js \
  test/status-telemetry-aggregate.test.js \
  test/meta-status.test.js \
  test/modat-neutral-context.test.js \
  test/modat-boundary-regression.test.js \
  test/modat-provider.test.js
```

Expected: all PASS.

- [ ] **Step 2: Review output for warnings and flaky timing**

Any warning introduced by the changed code is a failure to resolve before proceeding.

- [ ] **Step 3: Commit only if a concrete regression required a fix**

No empty verification commit.

---

### Task A16: Full Repository Gate

**Files:** no planned code changes.

- [ ] **Step 1: Run full Node test suite**

Run: `npm test`
Expected: PASS.

- [ ] **Step 2: Run repository verification**

Run: `npm run verify:repo`
Expected: PASS.

- [ ] **Step 3: Run public-release audit**

Run: `npm run audit:public`
Expected: PASS with no secret/canary exposure.

- [ ] **Step 4: Run shell/tooling checks when environment supports them**

Run: `npm run check`
Expected: PASS. If a required host tool is unavailable locally, CI remains authoritative for that specific tool and the limitation is recorded.

---

### Task A17: PR Diff and CI Review Gate

**Files:** no planned code changes.

- [ ] **Step 1: Review diff from plan base to head**

Check specifically for public API shape changes, raw indicators in telemetry, unbounded maps/sets, duplicate quality calculations, infrastructure evidence counted as reputation, and provider-order changes.

- [ ] **Step 2: Require Tooling smoke and CodeQL green on the exact head SHA**

Do not treat checks from an earlier SHA as evidence for the current head.

- [ ] **Step 3: Resolve every review finding before merge readiness**

The PR stays draft until this gate is clean.

---

### Task A18: Production Verification After Protected Merge

**Files:** no planned code changes.

**Interfaces:**
- Consumes the merged `main` SHA.
- Produces verified production parity evidence.

- [ ] **Step 1: Verify deployment source SHA**

Confirm Vercel production is `READY` and its Git SHA equals the merged `main` SHA.

- [ ] **Step 2: Smoke public metadata**

Verify `/api/para11ax/meta` retains the documented non-secret shape.

- [ ] **Step 3: Smoke authenticated status**

Verify aggregate telemetry fields are present, no raw events/indicators/secrets are present, and authentication remains required.

- [ ] **Step 4: Smoke representative enrichment**

Run one passive IP/domain lookup and confirm evidence quality and infrastructure context are present without changing maliciousness semantics.

- [ ] **Step 5: Inspect production runtime logs**

Check for new 4xx/5xx/error clusters attributable to the merged SHA.

- [ ] **Step 6: Record exact production SHA and verification evidence in the PR/release record**

No claim of completion before exact-SHA production parity is established.

---

## Execution Order

Run strictly in this order:

`A1 → A2 → A3 → A4 → A5 → A6 → A7 → A8 → A9 → A10 → A11 → A12 → A13 → A14 → A15 → A16 → A17 → A18`

Each A1-A14 task gets its own review gate and commit. A15-A18 are verification gates and only create commits when they expose a concrete defect requiring a minimal fix.

## Completion Criteria

The original MAX Intelligence Enrichment work is complete only when:

- evidence-quality fields are deterministic and polarity-independent;
- infrastructure context is independently corroborated and cannot vote on reputation;
- telemetry exposes bounded aggregate provider/status counts without indicator or secret leakage;
- authenticated status surfaces aggregates only;
- Modat remains neutral, fixed-host, bounded, and fail-closed;
- targeted and full repository gates pass on the exact head SHA;
- protected merge completes; and
- production exact-SHA smoke verification passes.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

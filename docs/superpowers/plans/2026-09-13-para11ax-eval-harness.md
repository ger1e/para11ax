# PARA11AX Internal Eval Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an offline, provider-neutral, deterministic PARA11AX evaluation harness that scores frozen synthetic workloads, produces privacy-bounded scorecards, compares candidates against a baseline, and supplies auditable evidence for routing decisions.

**Architecture:** Keep evaluation completely outside the production MCP request path. A frozen corpus in `evals/corpus/v1/` is validated and hashed, candidate result bundles are imported from disk, pure domain scorers produce normalized case results, and deterministic scorecard/comparison layers aggregate quality plus token/cost/latency evidence without copying raw candidate payloads into summaries. The CLI is a thin filesystem adapter over these pure modules and performs no network access or model calls.

**Tech Stack:** Node.js 24.x ESM, built-in `node:test`, built-in `node:crypto`, built-in `node:fs`, JSON fixtures, existing PARA11AX routing helpers, existing shell/CI checks.

**Spec:** `docs/superpowers/specs/2026-09-13-para11ax-eval-harness-design.md`

## Global Constraints

- No model-provider API calls, credentials, or network access in eval v1.
- No LLM-as-judge scoring.
- No production customer data, private incidents, internal credentials, or production IOCs in corpus or committed fixtures.
- `src/core/model-routing.js` remains normative production routing policy and must not depend on eval scorecards at runtime.
- Candidate outputs are evaluator input only and must never be copied into scorecards/comparison summaries.
- Missing `costUsd` and `latencyMs` remain `null`; never coerce them to zero.
- Full corpus is the only v1 evaluation profile; no partial-profile semantics in v1.
- Canonical object keys are recursively lexicographically sorted. The canonical serializer preserves provided array order; every schema-defined set-semantic array must be normalized before canonical serialization/hashing. Numeric scores are rounded to six decimal places.
- Scorecard hashes exclude `scorecardHash` itself and use SHA-256 prefixed with `sha256:`.
- Promotion policy lives in the corpus manifest and is consumed by comparison logic. The approved v1 policy is: no new critical hard failures; provenance/handoff regression <= 0.02; KQL regression <= 0.03; and either weighted score improves by >= 0.02 or weighted score is within 0.01 of baseline while known cost or known total token use drops by >= 20%.
- Any case with `humanReview.required=true` blocks promotion unless the result bundle contains an explicit completed review decision of `pass`.
- TDD for every implementation task. Each code task starts with a failing test and ends with a focused commit.
- Final repository completion requires exact-head Tooling smoke and CodeQL success before merge.

---

## File Structure

```text
evals/
  corpus/
    v1/
      manifest.json
      cti/cti-001.json
      provenance/provenance-001.json
      classification/classification-001.json
      attack/attack-001.json
      kql/kql-001.json
      handoff/handoff-001.json
      context/context-001.json
      routing/routing-001.json
      coding/coding-001.json
  fixtures/
    candidate-results/
      baseline-v1.json
      improved-v1.json

src/eval/
  canonical.js
  schemas.js
  corpus.js
  privacy.js
  score.js
  compare.js
  index.js
  domains/
    cti.js
    provenance.js
    classification.js
    attack.js
    kql.js
    handoff.js
    context.js
    routing.js
    coding.js

scripts/run-evals.mjs

test/
  eval-canonical.test.js
  eval-corpus.test.js
  eval-domains-core.test.js
  eval-domains-control.test.js
  eval-scorecard.test.js
  eval-compare.test.js
  eval-cli.test.js
  eval-docs.test.js

package.json
docs/PARA11AX-EVALS.md
docs/AGENT-ORCHESTRATION.md
```

The initial nine-case corpus is intentionally compact. Domain scorer unit tests provide positive, partial, and hard-failure coverage without bloating the committed corpus.

---

### Task 1: Canonical Serialization and Closed Eval Schemas

**Files:**
- Create: `src/eval/canonical.js`
- Create: `src/eval/schemas.js`
- Create: `test/eval-canonical.test.js`

**Interfaces:**
- Produces `canonicalize(value) -> JSON-safe value`
- Produces `canonicalJson(value) -> string`
- Produces `sha256Canonical(value) -> "sha256:<hex>"`
- Produces `roundScore(value) -> number`
- Produces `validateEvalCase(value) -> frozen validated case`
- Produces `validateResultBundle(value) -> frozen validated result bundle`

- [ ] **Step 1: Write failing canonical/schema tests**

Create `test/eval-canonical.test.js` with at least:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, roundScore, sha256Canonical } from '../src/eval/canonical.js';
import { validateEvalCase, validateResultBundle } from '../src/eval/schemas.js';

test('canonical JSON sorts object keys recursively and preserves supplied array order', () => {
  const value = { z: 1, a: { y: 2, b: 3 }, list: [{ q: 2, a: 1 }] };
  assert.equal(canonicalJson(value), '{"a":{"b":3,"y":2},"list":[{"a":1,"q":2}],"z":1}');
});

test('score rounding is stable to six decimals', () => {
  assert.equal(roundScore(0.123456789), 0.123457);
});

test('canonical hashes ignore object insertion order', () => {
  assert.equal(sha256Canonical({ a: 1, b: 2 }), sha256Canonical({ b: 2, a: 1 }));
});

test('result validation preserves null measurements and review state', () => {
  const result = validateResultBundle({
    schemaVersion: 'para11ax-eval-result-v1.0',
    corpusId: 'para11ax-internal-v1',
    runId: 'run-001',
    candidate: {
      provider: 'openai', model: 'example', family: 'example',
      effort: 'high', harness: 'manual', harnessVersion: '1.0.0',
    },
    measurements: { inputTokens: 10, outputTokens: 5, costUsd: null, latencyMs: null },
    cases: [{ caseId: 'cti-001', output: {}, measurements: {}, review: null }],
  });
  assert.equal(result.measurements.costUsd, null);
  assert.equal(result.measurements.latencyMs, null);
  assert.equal(result.cases[0].review, null);
});

test('completed human review requires an explicit pass/fail decision', () => {
  const baseCase = { caseId: 'cti-001', output: {}, measurements: {} };
  const make = review => ({
    schemaVersion: 'para11ax-eval-result-v1.0', corpusId: 'para11ax-internal-v1', runId: 'run-001',
    candidate: { provider:'x', model:'x', family:'x', effort:'high', harness:'x', harnessVersion:'1' },
    measurements: { inputTokens:0, outputTokens:0, costUsd:null, latencyMs:null },
    cases: [{ ...baseCase, review }],
  });
  assert.throws(() => validateResultBundle(make({ status: 'completed' })), /decision/);
  assert.doesNotThrow(() => validateResultBundle(make({ status: 'completed', decision: 'pass' })));
});
```

- [ ] **Step 2: Run red**

```bash
node --test test/eval-canonical.test.js
```

Expected: FAIL because the modules do not exist.

- [ ] **Step 3: Implement canonical helpers**

`src/eval/canonical.js`:

```js
import { createHash } from 'node:crypto';

export function roundScore(value) {
  if (!Number.isFinite(value)) throw new TypeError('score must be finite');
  return Number(value.toFixed(6));
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new TypeError('canonical JSON cannot encode non-finite numbers');
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256Canonical(value) {
  const hex = createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
  return `sha256:${hex}`;
}
```

- [ ] **Step 4: Implement explicit closed-schema validators**

`src/eval/schemas.js` exports:

```js
export const EVAL_CASE_SCHEMA = 'para11ax-eval-case-v1.0';
export const EVAL_RESULT_SCHEMA = 'para11ax-eval-result-v1.0';
export const EVAL_SCORECARD_SCHEMA = 'para11ax-eval-scorecard-v1.0';
export const EVAL_COMPARISON_SCHEMA = 'para11ax-eval-comparison-v1.0';
export const CORPUS_MANIFEST_SCHEMA = 'para11ax-eval-corpus-manifest-v1.0';
export const EVAL_DOMAINS = Object.freeze([
  'cti', 'provenance', 'classification', 'attack', 'kql',
  'handoff', 'context', 'routing', 'coding',
]);
```

Use local helpers `object()`, `exactKeys()`, `finiteNonNegative()`, and recursive freeze. Do not add a schema-library dependency.

`validateEvalCase()` accepts exactly:

```js
{ schemaVersion, caseId, domain, weight, input, expected }
```

Rules: exact schema; `caseId` matches `^[a-z]+-[0-9]{3}$`; domain in `EVAL_DOMAINS`; weight finite and `>0`; input/expected plain objects.

`validateResultBundle()` accepts exactly:

```js
{ schemaVersion, corpusId, runId, candidate, measurements, cases }
```

Candidate accepts exactly `provider`, `model`, `family`, `effort`, `harness`, `harnessVersion`, all non-empty strings.

Top-level measurements accept exactly `inputTokens`, `outputTokens`, `costUsd`, `latencyMs`; tokens are non-negative integers; cost/latency are null or finite non-negative numbers.

Case result accepts exactly:

```js
{ caseId, output, measurements, review }
```

`review` is either `null` or exactly:

```js
{ status: 'pending' }
```

or:

```js
{ status: 'completed', decision: 'pass' | 'fail' }
```

Case `measurements` is a plain object reserved for scalar per-case measurements; v1 scorer must not copy it into aggregate output except through explicitly recognized scalar fields later. Duplicate case IDs fail.

- [ ] **Step 5: Run green and commit**

```bash
node --test test/eval-canonical.test.js
git add src/eval/canonical.js src/eval/schemas.js test/eval-canonical.test.js
git commit -m "feat: define deterministic eval contracts"
```

---

### Task 2: Frozen Corpus, Manifest Policy, and Hash Verification

**Files:**
- Create: `src/eval/corpus.js`
- Create: `test/eval-corpus.test.js`
- Create: nine case files under `evals/corpus/v1/`
- Create: `evals/corpus/v1/manifest.json`

**Interfaces:**
- Produces `buildCorpusManifest({ corpusId, corpusVersion, releasedAt, weights, scorerVersions, promotionPolicy, cases })`
- Produces `verifyCorpus({ manifest, casesByPath }) -> frozen corpus descriptor`
- Produces `loadCorpusDirectory(rootPath)` using local filesystem only.

- [ ] **Step 1: Write failing corpus tests**

Tests must assert valid nine-domain corpus, mutation hash failure, duplicate case ID failure, unsafe path rejection, and manifest promotion-policy presence.

```js
assert.equal(corpus.manifest.promotionPolicy.minimumEfficiencyReductionRatio, 0.20);
assert.equal(corpus.cases.length, 9);
```

- [ ] **Step 2: Run red**

```bash
node --test test/eval-corpus.test.js
```

Expected: FAIL because corpus module/files do not exist.

- [ ] **Step 3: Implement corpus verification**

`loadCorpusDirectory()` reads only `manifest.json` and exact relative case paths from the manifest. Reject absolute paths, `..`, and backslashes.

`verifyCorpus()` must:

1. validate manifest schema and exact top-level keys;
2. validate every case with `validateEvalCase()`;
3. verify each case `sha256` against `sha256Canonical(case)`;
4. require unique paths and case IDs;
5. require exactly one initial case from each of the nine v1 domains;
6. require domain weights sum to `1` within `1e-9`;
7. require scorer version for every domain;
8. require exact v1 promotion-policy keys;
9. recompute `corpusHash` over the manifest with `corpusHash` removed and `cases` sorted by `caseId`;
10. return a recursively frozen descriptor.

Manifest promotion policy is the single runtime source of truth:

```json
{
  "provenanceMaxRegression": 0.02,
  "handoffMaxRegression": 0.02,
  "kqlMaxRegression": 0.03,
  "minimumWeightedImprovement": 0.02,
  "maximumWeightedRegressionForEfficiency": 0.01,
  "minimumEfficiencyReductionRatio": 0.20,
  "requireHumanReviewComplete": true
}
```

- [ ] **Step 4: Add nine synthetic/public-only cases**

Each case follows:

```json
{
  "schemaVersion": "para11ax-eval-case-v1.0",
  "caseId": "cti-001",
  "domain": "cti",
  "weight": 1,
  "input": {},
  "expected": {}
}
```

Contracts:

- `cti-001`: structured synthetic evidence; expected `entities` and `relationships`.
- `provenance-001`: evidence IDs `ev-1`, `ev-2`; expected `claims` with `claimId`, `allowedEvidenceIds`, `required`, `critical`; plus `criticalUnsupportedClaimIds`.
- `classification-001`: expected `items: [{id,label}]`, labels `ioc|ioa|ttp`.
- `attack-001`: expected unique `techniques`, e.g. `T1059.001`, `T1071.001`.
- `kql-001`: expected `requiredTables`, `forbiddenTokens`, `requiredRegexes`, `forbiddenRegexes`, `requiredHeaderKeys`.
- `handoff-001`: exact objective, constraints, decisions, nextActions, `allowCompleted:false`.
- `context-001`: input `items:[{id,tokens,durable,priority}]`, `maxTokens`; expected `requiredIds`.
- `routing-001`: task properties; expected route fields.
- `coding-001`: expected symbolic `defects` and `forbiddenFalsePositives`.

Use only reserved/synthetic material such as `CLIENT-ULTRAVIOLET`, RFC 5737 IPs like `198.51.100.23`, and `example.invalid`.

- [ ] **Step 5: Generate manifest hashes with the implementation, never by hand**

Run:

```bash
node --input-type=module <<'NODE'
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { buildCorpusManifest } from './src/eval/corpus.js';

const root = 'evals/corpus/v1';
const domains = ['cti','provenance','classification','attack','kql','handoff','context','routing','coding'];
const cases = [];
for (const domain of domains) {
  for (const name of readdirSync(join(root, domain)).sort()) {
    const path = join(root, domain, name);
    cases.push({ path: relative(root, path).replaceAll('\\', '/'), value: JSON.parse(readFileSync(path, 'utf8')) });
  }
}
const manifest = buildCorpusManifest({
  corpusId: 'para11ax-internal-v1', corpusVersion: '1.0.0', releasedAt: '2026-09-13',
  weights: { provenance:0.20, kql:0.15, cti:0.15, handoff:0.15, attack:0.10, classification:0.10, context:0.05, routing:0.05, coding:0.05 },
  scorerVersions: Object.fromEntries(domains.map(domain => [domain, '1.0.0'])),
  promotionPolicy: {
    provenanceMaxRegression:0.02, handoffMaxRegression:0.02, kqlMaxRegression:0.03,
    minimumWeightedImprovement:0.02, maximumWeightedRegressionForEfficiency:0.01,
    minimumEfficiencyReductionRatio:0.20, requireHumanReviewComplete:true
  },
  cases,
});
writeFileSync(join(root, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
NODE
```

- [ ] **Step 6: Run green and commit**

```bash
node --test test/eval-corpus.test.js
git add src/eval/corpus.js test/eval-corpus.test.js evals/corpus/v1
git commit -m "feat: add frozen PARA11AX eval corpus"
```

---

### Task 3: CTI, Provenance, Classification, and ATT&CK Scorers

**Files:**
- Create: `src/eval/domains/cti.js`
- Create: `src/eval/domains/provenance.js`
- Create: `src/eval/domains/classification.js`
- Create: `src/eval/domains/attack.js`
- Create: `test/eval-domains-core.test.js`

**Interfaces:**
Every scorer exports `SCORER_VERSION = '1.0.0'` and `score(caseValue, output)` returning:

```js
{
  score: 0,
  hardFail: false,
  criticalHardFail: false,
  violations: [],
  metrics: {},
  humanReview: { required: false, fields: [] },
  scorerVersion: '1.0.0'
}
```

Set-semantic output arrays such as violations and technique IDs must be unique and lexicographically sorted before return.

- [ ] **Step 1: Write failing positive/partial/hard-failure tests**

Required assertions include ATT&CK over-mapping lowering F1, unsupported CTI entity/relationship penalties, invalid provenance refs, critical unsupported claims, and classification invalid-label hard failure.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-domains-core.test.js
```

- [ ] **Step 3: Implement CTI + ATT&CK set scoring**

Use precision/recall/F1 over normalized stable strings. CTI entity key: `type:value`; relationship key: `source|type|target`. CTI score = mean(entity F1, relationship F1). Extra entities -> `unsupported_entity`; extra relationships -> `unsupported_relationship`.

ATT&CK score = F1 over expected vs actual technique IDs. Extra IDs reduce precision.

- [ ] **Step 4: Implement provenance scoring**

Candidate:

```json
{ "claims": [{ "claimId": "claim-1", "evidenceIds": ["ev-1"] }] }
```

Rules:

- missing required claim -> `missing_required_claim`;
- unknown claim ID -> `unsupported_claim`;
- unknown evidence ID -> `invalid_evidence_reference`;
- required claim without citation -> `missing_citation`;
- citation outside allowed set -> `unsupported_citation`;
- claim ID in `criticalUnsupportedClaimIds` -> `critical_unsupported_claim`, hard fail and critical hard fail;
- score = required-claim recall multiplied by citation precision, rounded to six decimals.

- [ ] **Step 5: Implement exact classification scoring**

Expected IDs/labels are exact. Unknown IDs count extra, missing expected IDs count incorrect, and labels outside `ioc|ioa|ttp` trigger `invalid_classification_label` + hard fail.

- [ ] **Step 6: Run green and commit**

```bash
node --test test/eval-domains-core.test.js
git add src/eval/domains test/eval-domains-core.test.js
git commit -m "feat: score core intelligence eval domains"
```

---

### Task 4: KQL, Handoff, Context, Routing, and Coding/Review Scorers

**Files:**
- Create: `src/eval/domains/kql.js`
- Create: `src/eval/domains/handoff.js`
- Create: `src/eval/domains/context.js`
- Create: `src/eval/domains/routing.js`
- Create: `src/eval/domains/coding.js`
- Create: `test/eval-domains-control.test.js`

**Interfaces:** Same scorer result contract as Task 3.

- [ ] **Step 1: Write failing tests**

Cover forbidden KQL dependencies, missing KQL structural requirements, changed handoff objective/constraints/decisions, premature completion, lost durable context, context budget overflow, routing mismatch/review omission, and coding defect precision/recall.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-domains-control.test.js
```

- [ ] **Step 3: Implement KQL structural scorer**

Candidate:

```json
{
  "query": "DeviceProcessEvents | where Timestamp > ago(1d)",
  "headers": {
    "title": "Synthetic Hunt",
    "description": "Synthetic",
    "suspiciousBehavior": "Synthetic",
    "mitreAttack": "T1059.001",
    "pyramidOfPain": "Behavior",
    "killChain": "Execution",
    "ctiUrls": ["https://example.invalid/cti"]
  }
}
```

Checks: required tables as whole words, forbidden tokens as whole words, required regexes, forbidden regexes, non-empty required headers. Forbidden dependency/pattern is hard fail. Score = passed checks / total checks. Never put query/header bodies in metrics or violations.

- [ ] **Step 4: Implement handoff scorer**

Candidate contains objective, constraints, decisions, nextActions, completed. Exact objective mismatch -> `objective_changed` critical hard fail. Lost required constraint -> `constraint_lost` critical hard fail. Lost decision -> `accepted_decision_lost` critical hard fail. `completed:true` while required next actions remain -> `premature_completion` critical hard fail.

- [ ] **Step 5: Implement context scorer**

Candidate `{ selectedIds: string[] }`. Unknown ID -> hard fail. Token sum > budget -> `context_budget_exceeded` critical hard fail. Missing required durable ID -> `durable_context_lost` critical hard fail. Score = `0.7 * durableRetention + 0.3 * evictionQuality`; if no comparable non-durable items, evictionQuality = 1.

- [ ] **Step 6: Implement routing scorer against production policy**

Import `routeModelTask` from `src/core/model-routing.js`. Compute normative route from case input and assert corpus `expected` agrees with that normative route. Candidate field mismatches produce `route_<field>_mismatch`. Omitted required independent review is a hard fail. Score exact-field accuracy across tier, reasoning effort, context policy, and two review flags.

- [ ] **Step 7: Implement coding/review scorer**

Candidate `{ defects: string[] }`. F1 against expected defect codes. Any expected `forbiddenFalsePositives` reported by candidate adds `forbidden_false_positive`.

- [ ] **Step 8: Run green and commit**

```bash
node --test test/eval-domains-control.test.js
git add src/eval/domains test/eval-domains-control.test.js
git commit -m "feat: score control and hunting eval domains"
```

---

### Task 5: Scorecard Engine, Review Projection, Privacy Guard, and Golden Determinism

**Files:**
- Create: `src/eval/privacy.js`
- Create: `src/eval/score.js`
- Create: `src/eval/index.js`
- Create: `test/eval-scorecard.test.js`
- Create: `evals/fixtures/candidate-results/baseline-v1.json`

**Interfaces:**
- Produces `scoreResultBundle({ corpus, resultBundle, evaluatorVersion = '1.0.0' })`
- Produces `assertAggregateOnlyScorecard(scorecard)`

- [ ] **Step 1: Write failing scorecard tests**

Tests must prove:

1. full corpus required and unknown case IDs rejected;
2. reversing result case order does not change scorecard bytes/hash;
3. same input twice is byte-identical;
4. distinctive marker strings seeded into raw output never appear in serialized scorecard;
5. null cost/latency remain null;
6. candidate result hash is present;
7. corpus ID/version/hash/scorer versions/promotion policy are recorded;
8. completed review is projected only as stable status/decision, never reviewer prose or raw output.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-scorecard.test.js
```

- [ ] **Step 3: Implement scorer dispatch and normalized case results**

Each scorecard case result has exactly:

```js
{
  caseId,
  domain,
  score,
  hardFail,
  criticalHardFail,
  violations,
  metrics,
  humanReview: {
    required,
    fields,
    reviewStatus,
    reviewDecision,
  },
  scorerVersion,
}
```

`reviewStatus` is `not_required`, `pending`, or `completed`; `reviewDecision` is `null`, `pass`, or `fail`. Sort case results by `caseId` before aggregation/hash.

- [ ] **Step 4: Aggregate domain/global metrics**

Domain object:

```js
{ score, cases, hardFailures, criticalHardFailures, humanReviewCases }
```

Global aggregate:

```js
{ weightedScore, hardFailures, criticalHardFailures, scoredCases, humanReviewCases }
```

Domain score uses case weights within domain. Global weighted score uses manifest weights. Round all scores to six decimals.

- [ ] **Step 5: Build reproducibility metadata and measurements**

Scorecard includes:

```js
{
  schemaVersion: 'para11ax-eval-scorecard-v1.0',
  evaluatorVersion: '1.0.0',
  corpus: {
    corpusId, corpusVersion, corpusHash, scorerVersions, promotionPolicy,
  },
  candidate,
  resultHash,
  aggregate,
  domains,
  cases,
  measurements: { inputTokens, outputTokens, totalTokens, costUsd, latencyMs },
  scorecardHash,
}
```

`resultHash = sha256Canonical(validatedResultBundle)`.

- [ ] **Step 6: Implement structural privacy guard**

Reject payload-bearing keys anywhere outside validated candidate metadata:

```js
const FORBIDDEN_KEYS = new Set([
  'output','query','text','body','evidence','prompt','content',
  'indicator','observable','clientName','serviceNow','raw',
]);
```

Case-result string fields are limited to IDs, domains, violation codes, review status/decision, and scorer versions. Metrics must be booleans, finite numbers, null, or bounded arrays of stable symbolic codes/IDs explicitly allowed by the scorer contract.

`scoreResultBundle()` calls `assertAggregateOnlyScorecard()` before hashing/return.

- [ ] **Step 7: Add baseline synthetic result fixture**

One result for each of nine case IDs. Seed `PRIVATE-MARKER-ULTRAVIOLET-9F4E` in a raw output value valid for one domain and assert it never occurs in scorecard serialization.

- [ ] **Step 8: Run green and commit**

```bash
node --test test/eval-scorecard.test.js
git add src/eval evals/fixtures/candidate-results/baseline-v1.json test/eval-scorecard.test.js
git commit -m "feat: build deterministic eval scorecards"
```

---

### Task 6: Baseline Comparison and Manifest-Driven Promotion Gate

**Files:**
- Create: `src/eval/compare.js`
- Modify: `src/eval/index.js`
- Create: `test/eval-compare.test.js`
- Create: `evals/fixtures/candidate-results/improved-v1.json`

**Interfaces:**
- Produces `compareScorecards({ baseline, candidate, requirePromotion = false })`
- Consumes promotion policy only from compatible scorecards' corpus metadata.

- [ ] **Step 1: Write failing compatibility/promotion tests**

Cover mismatched corpus/scorer/evaluator versions, critical regression blocking, provenance/handoff/KQL thresholds, >=20% cost efficiency path, >=20% token efficiency path, null measurement deltas, pending human review blocking, completed `pass` review allowing evaluation, and completed `fail` review blocking promotion.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-compare.test.js
```

- [ ] **Step 3: Implement strict compatibility**

Require exact equality for corpus ID/version/hash, scorer-version map, evaluator version, domain set, and promotion policy. Reject any mismatch.

- [ ] **Step 4: Implement scalar deltas**

```js
{
  weightedScore,
  hardFailures,
  criticalHardFailures,
  inputTokens,
  outputTokens,
  totalTokens,
  costUsd,
  latencyMs,
  domains: { [domain]: scoreDelta },
}
```

Nullable delta is `null` unless both values known.

- [ ] **Step 5: Implement manifest-driven promotion**

Read policy from `candidate.corpus.promotionPolicy` after compatibility succeeds. Promotion passes only if:

1. candidate critical hard failures <= baseline critical hard failures;
2. provenance delta >= `-provenanceMaxRegression`;
3. handoff delta >= `-handoffMaxRegression`;
4. KQL delta >= `-kqlMaxRegression`;
5. every required human review is completed with decision `pass`;
6. either weighted delta >= `minimumWeightedImprovement`, or weighted delta >= `-maximumWeightedRegressionForEfficiency` and one known efficiency reduction ratio is >= `minimumEfficiencyReductionRatio` (20%) for cost or total tokens.

Return stable reason codes only.

- [ ] **Step 6: Add improved fixture, run green, commit**

```bash
node --test test/eval-compare.test.js
git add src/eval/compare.js src/eval/index.js test/eval-compare.test.js evals/fixtures/candidate-results/improved-v1.json
git commit -m "feat: compare eval candidates against routing baselines"
```

---

### Task 7: Offline CLI and Package Scripts

**Files:**
- Create: `scripts/run-evals.mjs`
- Create: `test/eval-cli.test.js`
- Modify: `package.json`

**CLI:**

```text
npm run eval -- --results <file>
npm run eval -- --results <candidate> --baseline <baseline>
npm run eval -- --results <candidate> --baseline <baseline> --require-promotion
npm run eval -- --results <file> --json
npm run eval:verify
```

Exit codes: `0` valid; `2` bad args/input/corpus; `3` valid comparison but required promotion failed.

- [ ] **Step 1: Write failing `spawnSync` CLI tests**

Cover verify-corpus success, malformed results exit 2, JSON parsing, marker non-leakage, comparison promotion field, failed require-promotion exit 3, unknown flag exit 2, and missing results exit 2 unless verifying corpus.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-cli.test.js
```

- [ ] **Step 3: Implement dependency-free argument parsing**

Allow only:

```js
new Set(['--results','--baseline','--json','--verify-corpus','--require-promotion'])
```

Default corpus path: repo-root `evals/corpus/v1`. Read local UTF-8 JSON only. Human-readable output may include candidate metadata, hashes, aggregate/domain scores, scalar measurements, violation counts, review status, and promotion reason codes. Never print raw case output.

- [ ] **Step 4: Add package scripts**

```json
"eval": "node scripts/run-evals.mjs",
"eval:verify": "node scripts/run-evals.mjs --verify-corpus"
```

No new npm dependencies.

- [ ] **Step 5: Run green and commit**

```bash
node --test test/eval-cli.test.js
npm run eval:verify
npm run eval -- --results evals/fixtures/candidate-results/baseline-v1.json --json
npm run eval -- --results evals/fixtures/candidate-results/improved-v1.json --baseline evals/fixtures/candidate-results/baseline-v1.json --json
git add scripts/run-evals.mjs test/eval-cli.test.js package.json
git commit -m "feat: add offline PARA11AX eval CLI"
```

---

### Task 8: Operator Documentation and Routing-Evidence Contract

**Files:**
- Create: `docs/PARA11AX-EVALS.md`
- Modify: `docs/AGENT-ORCHESTRATION.md`
- Create: `test/eval-docs.test.js`

- [ ] **Step 1: Write failing documentation contract test**

Require both docs to reflect schema names and trust boundary, and require operator doc to contain exact thresholds: provenance/handoff `2%`, KQL `3%`, efficiency `20%`, weighted improvement `2%`, weighted efficiency tolerance `1%`.

Also require `npm run eval:verify`, no model API calls in v1, and no automatic routing mutation.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-docs.test.js
```

- [ ] **Step 3: Write `docs/PARA11AX-EVALS.md`**

Document purpose/trust boundary, corpus/version/hash model, candidate/review contract, domain scoring, hard failures vs weighted score, exact manifest-driven promotion policy, privacy boundary, CLI/exit codes, corpus versioning procedure, and routing review procedure.

- [ ] **Step 4: Update `docs/AGENT-ORCHESTRATION.md`**

Add a normative subsection: public benchmarks do not directly change routes; internal scorecard evidence is advisory input to a separately reviewed source change; production routing has no runtime dependency on eval results.

- [ ] **Step 5: Run green and commit**

```bash
node --test test/eval-docs.test.js
git add docs/PARA11AX-EVALS.md docs/AGENT-ORCHESTRATION.md test/eval-docs.test.js
git commit -m "docs: define PARA11AX eval operations"
```

---

### Task 9: CI Integration and Exact-Head Verification

**Files:**
- Modify: `package.json`
- Modify `.github/workflows/tooling-smoke.yml` only if it no longer runs `npm run check` at execution time.

- [ ] **Step 1: Integrate corpus verification into existing local/CI gate**

Change `check` to:

```json
"check": "bash -n scripts/*.sh && npm run lint:shell && npm run verify:repo && npm run audit:public && npm test && npm run eval:verify"
```

Because current Tooling smoke already runs `npm run check`, do not duplicate `npm run eval:verify` in the workflow unless that workflow has changed before execution.

- [ ] **Step 2: Run full deterministic verification**

```bash
npm ci --ignore-scripts
npm audit --omit=dev
npm run check
```

Expected: PASS with no blocking audit result.

- [ ] **Step 3: Static no-network import audit**

```bash
rg -n "from ['\"](node:https|node:http|https|http|undici|axios|got|openai|@anthropic)" src/eval scripts/run-evals.mjs
```

Expected: no matches.

- [ ] **Step 4: Reproduce canonical JSON output**

```bash
npm run eval:verify
npm run eval -- --results evals/fixtures/candidate-results/baseline-v1.json --json > /tmp/para11ax-baseline-scorecard.json
node -e "JSON.parse(require('node:fs').readFileSync('/tmp/para11ax-baseline-scorecard.json','utf8')); console.log('ok')"
```

Expected: `ok`.

- [ ] **Step 5: Commit CI integration**

```bash
git add package.json
git commit -m "ci: verify eval corpus in tooling gate"
```

- [ ] **Step 6: Open/update PR and freeze final head**

PR title: `Add deterministic PARA11AX internal eval harness`.

PR body summarizes offline/no-provider architecture, nine-domain corpus, deterministic scoring/comparison, review contract, privacy-bounded outputs, manifest-driven promotion gate, TDD evidence, and exact-head completion rule.

- [ ] **Step 7: Verify exact-head Tooling smoke and CodeQL**

Do not accept earlier-run green. Any patch changes head SHA and requires fresh exact-head evidence.

- [ ] **Step 8: Squash merge only after both gates succeed**

Use repository-allowed squash with `expected_head_sha` pinned to the verified final feature head. Verify PR `merged=true`, `main` points to returned squash commit, and merged commit contains eval harness files.

---

## Self-Review Checklist

- Every approved spec deliverable maps to a task above.
- No task requires provider keys, network access, or LLM judging.
- Promotion thresholds exactly match the approved spec: 2% provenance/handoff, 3% KQL, 2% quality improvement, 1% quality tolerance for efficiency, 20% cost-or-token efficiency.
- Promotion policy is stored in the corpus manifest and comparison consumes it rather than maintaining another runtime copy.
- Human review has an explicit result-bundle representation and promotion semantics.
- Scorecards record result hash, corpus/scorer versions, evaluator version, and promotion policy.
- Raw candidate outputs are absent from scorecards/comparisons by structure and privacy tests.
- Set-semantic arrays are normalized before canonical serialization; order-significant arrays are preserved.
- Nullable measurements remain nullable through validation, scorecard, and comparison.
- Production routing imports nothing from `src/eval/`; routing scorer may import production routing.
- Existing Tooling smoke stays authoritative through `npm run check`; avoid redundant workflow logic.

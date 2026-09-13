# PARA11AX Internal Eval Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an offline, provider-neutral, deterministic PARA11AX evaluation harness that scores frozen synthetic workloads, produces privacy-bounded scorecards, compares candidates against a baseline, and supplies auditable evidence for routing decisions.

**Architecture:** Keep evaluation completely outside the production MCP request path. A frozen corpus in `evals/corpus/v1/` is validated and hashed, candidate result bundles are imported from disk, pure domain scorers produce normalized case results, and a deterministic scorecard/comparison layer aggregates quality plus token/cost/latency evidence without copying raw candidate payloads into summaries. The CLI is a thin filesystem adapter over these pure modules and performs no network access or model calls.

**Tech Stack:** Node.js 24.x ESM, built-in `node:test`, built-in `node:crypto`, built-in `node:fs`, JSON fixtures, existing PARA11AX routing helpers, existing shell/CI checks.

**Spec:** `docs/superpowers/specs/2026-09-13-para11ax-eval-harness-design.md`

## Global Constraints

- No model-provider API calls, credentials, or network access in eval v1.
- No LLM-as-judge scoring.
- No production customer data, private incidents, internal credentials, or production IOCs in the corpus or committed fixtures.
- `src/core/model-routing.js` remains the normative production routing policy and must not depend on eval scorecards at runtime.
- Candidate outputs are evaluator input only and must never be copied into scorecards/comparison summaries.
- Missing `costUsd` and `latencyMs` remain `null`; they are never coerced to zero.
- Full corpus is the only v1 evaluation profile; no partial-profile semantics in v1.
- Canonical JSON uses recursively sorted object keys, array order normalized where the schema declares set semantics, and numeric scores rounded to six decimal places before hashing.
- Scorecard hashes exclude the `scorecardHash` field itself and use SHA-256 prefixed with `sha256:`.
- Promotion default: no new critical hard failures; provenance/handoff regression <= 0.02; KQL regression <= 0.03; and either weighted score improves by >= 0.02 or weighted score is within 0.01 of baseline while known cost drops by >= 10% or known total token use drops by >= 15%.
- Human-review-required cases block automatic promotion until marked reviewed.
- TDD for every implementation task. Each code task starts with a failing test and ends with a focused commit.
- Final repository completion requires exact-head Tooling smoke and CodeQL success before merge.

---

## File Structure

Create or modify the following files. Keep these boundaries stable unless a test proves the decomposition is wrong.

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
  canonical.js          # stable serialization, number normalization, SHA-256
  schemas.js            # closed-schema validation for case/result/scorecard metadata
  corpus.js             # corpus loading/manifest verification/hash verification
  privacy.js            # aggregate-only scorecard/comparison structural guard
  score.js              # dispatch domain scorer, aggregate cases/domains, hash scorecard
  compare.js            # baseline/candidate compatibility and promotion gate
  index.js              # public eval exports
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

scripts/
  run-evals.mjs         # filesystem CLI adapter only

test/
  eval-canonical.test.js
  eval-corpus.test.js
  eval-domains-core.test.js
  eval-domains-control.test.js
  eval-scorecard.test.js
  eval-compare.test.js
  eval-cli.test.js

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
- Produces: `canonicalize(value) -> JSON-safe value`
- Produces: `canonicalJson(value) -> string`
- Produces: `sha256Canonical(value) -> "sha256:<hex>"`
- Produces: `roundScore(value) -> number`
- Produces: `validateEvalCase(value) -> frozen validated case`
- Produces: `validateResultBundle(value) -> frozen validated result bundle`
- Produces schema constants used by later tasks.

- [ ] **Step 1: Write canonicalization tests first**

Create `test/eval-canonical.test.js` with tests equivalent to:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalJson,
  roundScore,
  sha256Canonical,
} from '../src/eval/canonical.js';
import {
  validateEvalCase,
  validateResultBundle,
} from '../src/eval/schemas.js';

test('canonical JSON sorts object keys recursively and preserves array order', () => {
  const value = { z: 1, a: { y: 2, b: 3 }, list: [{ q: 2, a: 1 }] };
  assert.equal(
    canonicalJson(value),
    '{"a":{"b":3,"y":2},"list":[{"a":1,"q":2}],"z":1}'
  );
});

test('score rounding is stable to six decimals', () => {
  assert.equal(roundScore(0.123456789), 0.123457);
  assert.equal(roundScore(1), 1);
});

test('canonical hashes are independent of object key insertion order', () => {
  assert.equal(
    sha256Canonical({ a: 1, b: 2 }),
    sha256Canonical({ b: 2, a: 1 })
  );
});

test('result validation preserves null measurements and rejects non-finite values', () => {
  const valid = validateResultBundle({
    schemaVersion: 'para11ax-eval-result-v1.0',
    corpusId: 'para11ax-internal-v1',
    runId: 'run-001',
    candidate: {
      provider: 'openai', model: 'example', family: 'example',
      effort: 'high', harness: 'manual', harnessVersion: '1.0.0',
    },
    measurements: { inputTokens: 10, outputTokens: 5, costUsd: null, latencyMs: null },
    cases: [{ caseId: 'cti-001', output: {}, measurements: {} }],
  });
  assert.equal(valid.measurements.costUsd, null);
  assert.equal(valid.measurements.latencyMs, null);

  assert.throws(() => validateResultBundle({
    ...valid,
    measurements: { ...valid.measurements, latencyMs: Infinity },
  }), /latencyMs/);
});
```

- [ ] **Step 2: Run the focused test and verify red**

Run:

```bash
node --test test/eval-canonical.test.js
```

Expected: FAIL because `src/eval/canonical.js` and `src/eval/schemas.js` do not exist.

- [ ] **Step 3: Implement stable canonical helpers**

Create `src/eval/canonical.js` with the actual behavior:

```js
import { createHash } from 'node:crypto';

export function roundScore(value) {
  if (!Number.isFinite(value)) throw new TypeError('score must be finite');
  return Number(value.toFixed(6));
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map(key => [key, canonicalize(value[key])])
    );
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

- [ ] **Step 4: Implement closed-schema validators**

Create `src/eval/schemas.js`. Do not add a schema-library dependency. Use small explicit helpers and reject unknown top-level keys so accidental payload growth fails closed.

Define constants:

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

Use validation helpers with these exact rules:

```js
function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function exactKeys(value, allowed, label) {
  const extra = Object.keys(value).filter(key => !allowed.includes(key));
  if (extra.length) throw new TypeError(`${label} contains unknown keys: ${extra.join(', ')}`);
}

function finiteNonNegative(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  if (!Number.isFinite(value) || value < 0) throw new TypeError(`${label} must be a finite non-negative number`);
  return value;
}
```

`validateEvalCase()` accepts exactly:

```js
{
  schemaVersion,
  caseId,
  domain,
  weight,
  input,
  expected,
}
```

Rules: schema must be `para11ax-eval-case-v1.0`; `caseId` matches `^[a-z]+-[0-9]{3}$`; domain is in `EVAL_DOMAINS`; weight is finite and `> 0`; `input` and `expected` are objects.

`validateResultBundle()` accepts exactly:

```js
{
  schemaVersion,
  corpusId,
  runId,
  candidate,
  measurements,
  cases,
}
```

Candidate accepts exactly `provider`, `model`, `family`, `effort`, `harness`, `harnessVersion`, all non-empty strings. Measurements accepts exactly `inputTokens`, `outputTokens`, `costUsd`, `latencyMs`; tokens must be finite non-negative integers, cost and latency may be `null` or finite non-negative numbers. Case results accept exactly `caseId`, `output`, `measurements`; `output` and `measurements` must be objects. Duplicate result `caseId` values fail.

Return `structuredClone()`d, recursively frozen values so callers cannot mutate validated contracts.

- [ ] **Step 5: Run focused tests green**

```bash
node --test test/eval-canonical.test.js
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/eval/canonical.js src/eval/schemas.js test/eval-canonical.test.js
git commit -m "feat: define deterministic eval contracts"
```

---

### Task 2: Frozen Corpus, Manifest Hashes, and Corpus Verification

**Files:**
- Create: `src/eval/corpus.js`
- Create: `test/eval-corpus.test.js`
- Create: all nine case files under `evals/corpus/v1/`
- Create: `evals/corpus/v1/manifest.json`

**Interfaces:**
- Consumes: `validateEvalCase`, `canonicalJson`, `sha256Canonical`
- Produces: `buildCorpusManifest({ corpusId, corpusVersion, releasedAt, weights, scorerVersions, cases })`
- Produces: `verifyCorpus({ manifest, casesByPath }) -> frozen corpus descriptor`
- Produces: `loadCorpusDirectory(rootPath) -> { manifest, casesByPath }` using local filesystem only.

- [ ] **Step 1: Write failing corpus tests**

Create `test/eval-corpus.test.js` with these cases:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import {
  loadCorpusDirectory,
  verifyCorpus,
} from '../src/eval/corpus.js';

const root = resolve('evals/corpus/v1');

test('v1 corpus verifies all case hashes and corpus hash', () => {
  const loaded = loadCorpusDirectory(root);
  const corpus = verifyCorpus(loaded);
  assert.equal(corpus.manifest.corpusId, 'para11ax-internal-v1');
  assert.equal(corpus.cases.length, 9);
  assert.equal(new Set(corpus.cases.map(item => item.domain)).size, 9);
});

test('corpus verification fails when a case is mutated after manifest creation', () => {
  const loaded = loadCorpusDirectory(root);
  const paths = Object.keys(loaded.casesByPath);
  const first = paths[0];
  const mutated = structuredClone(loaded);
  mutated.casesByPath[first].expected = { changed: true };
  assert.throws(() => verifyCorpus(mutated), /hash mismatch/);
});

test('corpus rejects duplicate case IDs', () => {
  const loaded = loadCorpusDirectory(root);
  const paths = Object.keys(loaded.casesByPath);
  const mutated = structuredClone(loaded);
  mutated.casesByPath[paths[1]].caseId = mutated.casesByPath[paths[0]].caseId;
  assert.throws(() => verifyCorpus(mutated), /duplicate caseId/);
});
```

- [ ] **Step 2: Run focused test and verify red**

```bash
node --test test/eval-corpus.test.js
```

Expected: FAIL because `src/eval/corpus.js` and corpus files do not exist.

- [ ] **Step 3: Implement corpus loading and hash verification**

`src/eval/corpus.js` must:

1. read only `manifest.json` and the exact relative paths listed by that manifest;
2. reject paths containing `..`, absolute paths, or backslashes;
3. validate every loaded case with `validateEvalCase()`;
4. verify each `sha256` against `sha256Canonical(case)`;
5. verify unique `caseId` and path values;
6. require exactly the nine v1 domains once in the initial full profile;
7. recompute `corpusHash` over the manifest with `corpusHash` removed and cases sorted by `caseId`;
8. freeze the returned descriptor.

Manifest shape:

```json
{
  "schemaVersion": "para11ax-eval-corpus-manifest-v1.0",
  "corpusId": "para11ax-internal-v1",
  "corpusVersion": "1.0.0",
  "releasedAt": "2026-09-13",
  "profile": "full",
  "weights": {
    "provenance": 0.20,
    "kql": 0.15,
    "cti": 0.15,
    "handoff": 0.15,
    "attack": 0.10,
    "classification": 0.10,
    "context": 0.05,
    "routing": 0.05,
    "coding": 0.05
  },
  "scorerVersions": {
    "cti": "1.0.0",
    "provenance": "1.0.0",
    "classification": "1.0.0",
    "attack": "1.0.0",
    "kql": "1.0.0",
    "handoff": "1.0.0",
    "context": "1.0.0",
    "routing": "1.0.0",
    "coding": "1.0.0"
  },
  "cases": [],
  "corpusHash": "sha256:..."
}
```

Do not hand-edit hash values. `buildCorpusManifest()` is the single source of truth used to generate them.

- [ ] **Step 4: Add the nine synthetic v1 cases**

Use synthetic/public-only data. Each file must follow this shape:

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

Use these exact domain contracts:

- `cti-001`: input has synthetic evidence IDs and structured facts; expected has `entities` and `relationships` arrays.
- `provenance-001`: input has evidence IDs `ev-1`, `ev-2`; expected has `claims` where each claim has `claimId`, `allowedEvidenceIds`, `required`, `critical`.
- `classification-001`: expected has `items: [{ id, label }]`, labels limited to `ioc`, `ioa`, `ttp`.
- `attack-001`: expected has a unique `techniques` array using synthetic expected ATT&CK IDs such as `T1059.001` and `T1071.001`.
- `kql-001`: expected has `requiredTables`, `forbiddenTokens`, `requiredRegexes`, `forbiddenRegexes`, and `requiredHeaderKeys`.
- `handoff-001`: expected has exact `objective`, `constraints`, `decisions`, `nextActions` and `allowCompleted: false`.
- `context-001`: input has `items: [{ id, tokens, durable, priority }]` plus `maxTokens`; expected has `requiredIds`.
- `routing-001`: input has task properties; expected has `tier`, `reasoningEffort`, `contextPolicy`, `requireIndependentReview`, `requireDifferentFamilyReviewer`.
- `coding-001`: expected has `defects`, each a stable symbolic defect code.

Use obviously synthetic names like `CLIENT-ULTRAVIOLET`, `198.51.100.23`, and `example.invalid` so there is no ambiguity that the corpus is not production intelligence.

- [ ] **Step 5: Generate the manifest deterministically**

After creating the case files, run this exact local command once `buildCorpusManifest()` exists:

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
  corpusId: 'para11ax-internal-v1',
  corpusVersion: '1.0.0',
  releasedAt: '2026-09-13',
  weights: { provenance:0.20, kql:0.15, cti:0.15, handoff:0.15, attack:0.10, classification:0.10, context:0.05, routing:0.05, coding:0.05 },
  scorerVersions: Object.fromEntries(domains.map(domain => [domain, '1.0.0'])),
  cases,
});
writeFileSync(join(root, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
NODE
```

- [ ] **Step 6: Run corpus tests green**

```bash
node --test test/eval-corpus.test.js
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
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
Each module exports `SCORER_VERSION = '1.0.0'` and `score(caseValue, output)` returning:

```js
{
  score: 0..1,
  hardFail: boolean,
  criticalHardFail: boolean,
  violations: string[],
  metrics: object,
  humanReview: { required: boolean, fields: string[] },
  scorerVersion: '1.0.0'
}
```

Violation arrays must be unique and lexicographically sorted before return.

- [ ] **Step 1: Write failing domain tests**

Cover exact-match, partial, over-generation, and critical failure cases.

Representative expectations:

```js
assert.deepEqual(scoreClassification(caseValue, {
  items: [{ id: 'x', label: 'ioc' }, { id: 'y', label: 'ttp' }],
}).metrics, { correct: 2, expected: 2, extra: 0 });

assert.equal(scoreAttack(caseValue, {
  techniques: ['T1059.001', 'T9999.999'],
}).score < 1, true);

assert.equal(scoreProvenance(caseValue, {
  claims: [{ claimId: 'critical-false-claim', evidenceIds: [] }],
}).criticalHardFail, true);
```

- [ ] **Step 2: Run red**

```bash
node --test test/eval-domains-core.test.js
```

Expected: FAIL because scorer modules do not exist.

- [ ] **Step 3: Implement common set-metric behavior locally without a shared premature abstraction**

For CTI and ATT&CK use precision/recall/F1:

```js
function f1({ expected, actual }) {
  const expectedSet = new Set(expected);
  const actualSet = new Set(actual);
  const tp = [...actualSet].filter(item => expectedSet.has(item)).length;
  const precision = actualSet.size ? tp / actualSet.size : 0;
  const recall = expectedSet.size ? tp / expectedSet.size : 1;
  const score = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { tp, precision, recall, score };
}
```

Normalize CTI entities as `type:value` and relationships as `source|type|target`, then average entity F1 and relationship F1. Extra invented relationships add violation `unsupported_relationship`; extra entities add `unsupported_entity`. No human review in v1 structured CTI cases.

- [ ] **Step 4: Implement provenance scoring**

Candidate output shape:

```json
{ "claims": [{ "claimId": "claim-1", "evidenceIds": ["ev-1"] }] }
```

Rules:

- expected required claim missing -> `missing_required_claim`;
- unknown candidate claim ID -> `unsupported_claim`;
- unknown evidence ID -> `invalid_evidence_reference`;
- required claim with no evidence -> `missing_citation`;
- citation not in that claim's `allowedEvidenceIds` -> `unsupported_citation`;
- unknown claim whose ID is listed in case `expected.criticalUnsupportedClaimIds` -> `critical_unsupported_claim` and both hard-fail flags true;
- score = supported required claims / total required claims, multiplied by citation precision; round at six decimals.

- [ ] **Step 5: Implement classification scoring**

Exact ID/label accuracy. Unknown IDs count as `extra`; missing expected IDs count incorrect. Invalid labels trigger `invalid_classification_label` and hard fail.

- [ ] **Step 6: Run green**

```bash
node --test test/eval-domains-core.test.js
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
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

**Interfaces:**
Same scorer result contract as Task 3.

- [ ] **Step 1: Write failing KQL/control-plane tests**

Required cases:

```js
assert.equal(scoreKql(kqlCase, { query: 'DeviceProcessEvents | where Timestamp > ago(1d)', headers: {} }).hardFail, false);
assert.equal(scoreKql(kqlCase, { query: 'Sysmon | take 10', headers: {} }).hardFail, true);
assert.equal(scoreHandoff(handoffCase, { ...expected, constraints: [] }).criticalHardFail, true);
assert.equal(scoreContext(contextCase, { selectedIds: ['scratch'] }).criticalHardFail, true);
assert.equal(scoreRouting(routingCase, { ...expectedRoute, requireIndependentReview: false }).hardFail, true);
assert.equal(scoreCoding(codingCase, { defects: ['missing_validation'] }).score <= 1, true);
```

- [ ] **Step 2: Run red**

```bash
node --test test/eval-domains-control.test.js
```

Expected: FAIL because modules do not exist.

- [ ] **Step 3: Implement KQL structural scorer**

Candidate output:

```json
{
  "query": "...",
  "headers": {
    "title": "...",
    "description": "...",
    "suspiciousBehavior": "...",
    "mitreAttack": "...",
    "pyramidOfPain": "...",
    "killChain": "...",
    "ctiUrls": ["https://example.invalid/..." ]
  }
}
```

Checks:

- every `requiredTables` token appears as a whole-word regex;
- any `forbiddenTokens` whole-word match -> `forbidden_dependency` and hard fail;
- every `requiredRegexes` source compiles and matches query;
- any `forbiddenRegexes` match -> `forbidden_pattern` and hard fail;
- every required header key exists and is non-empty;
- score = passed checks / total checks;
- do not copy query text or headers into metrics/violations.

- [ ] **Step 4: Implement handoff scorer**

Candidate output shape:

```json
{
  "objective": "...",
  "constraints": ["..."],
  "decisions": ["..."],
  "nextActions": ["..."],
  "completed": false
}
```

Normalize arrays as sorted unique strings only where the case contract marks them set-like. Exact objective mismatch -> `objective_changed` + critical hard fail. Missing any required constraint -> `constraint_lost` + critical hard fail. Missing accepted decision -> `accepted_decision_lost` + critical hard fail. `completed:true` while expected `nextActions` is non-empty -> `premature_completion` + critical hard fail.

- [ ] **Step 5: Implement context scorer**

Candidate output: `{ selectedIds: string[] }`.

Rules:

- unknown selected ID -> hard fail `unknown_context_item`;
- selected token sum > `input.maxTokens` -> critical hard fail `context_budget_exceeded`;
- any required durable ID missing -> critical hard fail `durable_context_lost`;
- score = 0.7 * durableRetention + 0.3 * evictionQuality;
- eviction quality is the fraction of selected non-durable items that are not lower priority than an omitted non-durable item. If there are no comparable non-durable items, evictionQuality = 1.

- [ ] **Step 6: Implement routing scorer against normative routing policy**

Import `routeModelTask` from `src/core/model-routing.js` and compute normative output from the case input. The case's `expected` route remains a frozen corpus assertion; test that it agrees with `routeModelTask()` so corpus drift becomes visible.

Candidate route mismatches are violations named `route_<field>_mismatch`. Missing required independent review on a high-risk/repeated-failure normative route is a hard fail. Score is exact-field accuracy across `tier`, `reasoningEffort`, `contextPolicy`, `requireIndependentReview`, and `requireDifferentFamilyReviewer`.

- [ ] **Step 7: Implement coding/review scorer**

Candidate output: `{ defects: string[] }`.

Expected contains `defects` and optional `forbiddenFalsePositives`. Score is F1 over expected defect codes. Any forbidden false-positive defect code adds `forbidden_false_positive`. This domain has no source-code execution in v1.

- [ ] **Step 8: Run green**

```bash
node --test test/eval-domains-control.test.js
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/eval/domains test/eval-domains-control.test.js
git commit -m "feat: score control and hunting eval domains"
```

---

### Task 5: Scorecard Engine, Aggregate Metrics, Privacy Guard, and Golden Determinism

**Files:**
- Create: `src/eval/privacy.js`
- Create: `src/eval/score.js`
- Create: `src/eval/index.js`
- Create: `test/eval-scorecard.test.js`
- Create: `evals/fixtures/candidate-results/baseline-v1.json`

**Interfaces:**
- Produces: `scoreResultBundle({ corpus, resultBundle, evaluatorVersion = '1.0.0' }) -> frozen scorecard`
- Produces: `assertAggregateOnlyScorecard(scorecard) -> true or throws`
- Produces: public exports from `src/eval/index.js`.

- [ ] **Step 1: Write failing scorecard tests**

Tests must cover:

1. full corpus required;
2. case result order does not change scorecard bytes/hash;
3. same input twice gives byte-identical canonical JSON;
4. marker strings seeded into raw output do not occur in serialized scorecard;
5. `costUsd:null` and `latencyMs:null` remain null;
6. scorecard contains only case IDs, scalar metrics, violations, review state, versions, candidate metadata, hashes, and measurements.

Example determinism assertion:

```js
const a = scoreResultBundle({ corpus, resultBundle });
const b = scoreResultBundle({ corpus, resultBundle: {
  ...resultBundle,
  cases: [...resultBundle.cases].reverse(),
}});
assert.equal(canonicalJson(a), canonicalJson(b));
assert.equal(a.scorecardHash, b.scorecardHash);
```

- [ ] **Step 2: Run red**

```bash
node --test test/eval-scorecard.test.js
```

Expected: FAIL because score engine does not exist.

- [ ] **Step 3: Implement scorer dispatch and normalized case result**

`score.js` maps domain -> scorer function with no dynamic import. Each case result emitted into the scorecard has exactly:

```js
{
  caseId,
  domain,
  score,
  hardFail,
  criticalHardFail,
  violations,
  metrics,
  humanReview,
  scorerVersion,
}
```

Sort case results by `caseId` before aggregate calculation and hashing.

- [ ] **Step 4: Implement domain and weighted aggregates**

For each domain:

```js
{
  score,
  cases,
  hardFailures,
  criticalHardFailures,
  humanReviewCases,
}
```

Domain score is the weighted average of case scores using case `weight` inside that domain. Global `weightedScore` applies manifest domain weights to domain scores.

Top-level aggregate:

```js
{
  weightedScore,
  hardFailures,
  criticalHardFailures,
  scoredCases,
  humanReviewCases,
}
```

All score values use `roundScore()`.

- [ ] **Step 5: Implement scorecard measurements**

Expose only:

```js
{
  inputTokens,
  outputTokens,
  totalTokens,
  costUsd,
  latencyMs,
}
```

`totalTokens = inputTokens + outputTokens`. Do not derive cost or latency when missing.

- [ ] **Step 6: Implement privacy structural guard**

`privacy.js` must recursively reject any scorecard key named or ending in these payload-bearing names:

```js
const FORBIDDEN_KEYS = new Set([
  'output', 'query', 'text', 'body', 'evidence', 'prompt', 'content',
  'indicator', 'observable', 'clientName', 'serviceNow', 'raw',
]);
```

Also reject strings under case results except stable identifiers/codes/scorer versions. Candidate metadata strings are allowed only under `candidate`. This makes privacy a shape invariant rather than unreliable secret-string guessing.

Before returning a scorecard, `scoreResultBundle()` calls `assertAggregateOnlyScorecard()`.

- [ ] **Step 7: Hash the scorecard**

Create the scorecard without `scorecardHash`, canonicalize it, then add:

```js
scorecardHash: sha256Canonical(scorecardWithoutHash)
```

Return a recursively frozen scorecard.

- [ ] **Step 8: Add the baseline synthetic result fixture**

`baseline-v1.json` must contain one output for each of the nine case IDs. Include distinctive marker strings such as `PRIVATE-MARKER-ULTRAVIOLET-9F4E` inside one raw candidate output field that is valid for that domain. The scorecard test must prove this marker never appears in `canonicalJson(scorecard)`.

- [ ] **Step 9: Run green**

```bash
node --test test/eval-scorecard.test.js
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/eval evals/fixtures/candidate-results/baseline-v1.json test/eval-scorecard.test.js
git commit -m "feat: build deterministic eval scorecards"
```

---

### Task 6: Baseline Comparison and Explicit Promotion Gate

**Files:**
- Create: `src/eval/compare.js`
- Create: `test/eval-compare.test.js`
- Create: `evals/fixtures/candidate-results/improved-v1.json`
- Modify: `src/eval/index.js`

**Interfaces:**
- Produces: `compareScorecards({ baseline, candidate, requirePromotion = false })`
- Produces: `DEFAULT_PROMOTION_POLICY` constant.

- [ ] **Step 1: Write failing comparison tests**

Required tests:

```js
assert.throws(() => compareScorecards({ baseline, candidate: wrongCorpus }), /corpus/);
assert.equal(compareScorecards({ baseline, candidate: better }).promotion.passed, true);
assert.equal(compareScorecards({ baseline, candidate: criticalRegression }).promotion.passed, false);
assert.equal(compareScorecards({ baseline, candidate: cheaperButEqual }).promotion.passed, true);
assert.equal(compareScorecards({ baseline, candidate: missingCost }).deltas.costUsd, null);
```

Also test that a higher weighted score cannot override a new critical hard failure.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-compare.test.js
```

Expected: FAIL because `compare.js` does not exist.

- [ ] **Step 3: Implement strict compatibility checks**

Reject comparisons unless these fields match exactly:

- corpus ID;
- corpus version;
- corpus hash;
- scorer-version map;
- evaluator version;
- domain set.

- [ ] **Step 4: Implement deltas**

Return scalar deltas only:

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

For nullable measurements, delta is `null` unless both baseline and candidate values are known.

- [ ] **Step 5: Implement exact default promotion policy**

```js
export const DEFAULT_PROMOTION_POLICY = Object.freeze({
  provenanceMaxRegression: 0.02,
  handoffMaxRegression: 0.02,
  kqlMaxRegression: 0.03,
  minimumWeightedImprovement: 0.02,
  maximumWeightedRegressionForEfficiency: 0.01,
  minimumCostReductionRatio: 0.10,
  minimumTokenReductionRatio: 0.15,
  requireHumanReviewComplete: true,
});
```

Promotion passes only if:

1. candidate critical hard failures <= baseline critical hard failures;
2. provenance, handoff, and KQL deltas satisfy regression limits;
3. no candidate human-review cases remain when review completion is required;
4. either weighted delta >= 0.02, or weighted delta >= -0.01 and at least one known efficiency criterion passes:
   - `(baselineCost - candidateCost) / baselineCost >= 0.10`, when both costs are non-null and baseline cost > 0; OR
   - `(baselineTokens - candidateTokens) / baselineTokens >= 0.15`, when baseline total tokens > 0.

Return stable reason codes, never prose copied from model output.

- [ ] **Step 6: Add improved fixture and run green**

`improved-v1.json` should improve at least one quality domain and reduce total tokens enough to exercise the promotion path without changing corpus identity.

```bash
node --test test/eval-compare.test.js
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/eval/compare.js src/eval/index.js test/eval-compare.test.js evals/fixtures/candidate-results/improved-v1.json
git commit -m "feat: compare eval candidates against routing baselines"
```

---

### Task 7: Offline CLI, Package Scripts, and Golden Reproduction

**Files:**
- Create: `scripts/run-evals.mjs`
- Create: `test/eval-cli.test.js`
- Modify: `package.json`

**Interfaces:**
CLI contracts:

```text
npm run eval -- --results <file>
npm run eval -- --results <candidate> --baseline <baseline>
npm run eval -- --results <candidate> --baseline <baseline> --require-promotion
npm run eval -- --results <file> --json
npm run eval:verify
```

Exit codes:
- `0`: valid evaluation/comparison and promotion either not requested or passed;
- `2`: invalid CLI arguments or malformed/invalid input/corpus;
- `3`: valid comparison but explicit `--require-promotion` failed.

- [ ] **Step 1: Write failing CLI tests using `spawnSync`**

Cover:

- `--verify-corpus` exits 0;
- malformed results exits 2;
- JSON mode parses as JSON and does not contain raw marker strings;
- comparison output contains promotion result;
- failed `--require-promotion` exits 3;
- invoking without `--results` unless `--verify-corpus` exits 2.

Use only local files and set a minimal environment. Do not mock network because the CLI must not import any network client at all.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-cli.test.js
```

Expected: FAIL because CLI does not exist.

- [ ] **Step 3: Implement argument parsing without adding dependencies**

Accepted flags only:

```js
new Set([
  '--results', '--baseline', '--json', '--verify-corpus', '--require-promotion',
])
```

Unknown flags fail with exit 2. Paths are read as UTF-8 JSON. Default corpus path resolves from repo root to `evals/corpus/v1`.

Human-readable output must contain only candidate metadata, hashes, aggregate/domain scores, measurement scalars, violation counts, and promotion reason codes. It must never print raw case output.

- [ ] **Step 4: Add package scripts**

Modify `package.json` scripts to include:

```json
"eval": "node scripts/run-evals.mjs",
"eval:verify": "node scripts/run-evals.mjs --verify-corpus"
```

Do not change the Node engine or add packages.

- [ ] **Step 5: Run CLI tests and direct commands**

```bash
node --test test/eval-cli.test.js
npm run eval:verify
npm run eval -- --results evals/fixtures/candidate-results/baseline-v1.json --json
npm run eval -- --results evals/fixtures/candidate-results/improved-v1.json --baseline evals/fixtures/candidate-results/baseline-v1.json --json
```

Expected: all commands exit 0 and JSON outputs parse.

- [ ] **Step 6: Commit**

```bash
git add scripts/run-evals.mjs test/eval-cli.test.js package.json
git commit -m "feat: add offline PARA11AX eval CLI"
```

---

### Task 8: Documentation and Routing-Evidence Contract

**Files:**
- Create: `docs/PARA11AX-EVALS.md`
- Modify: `docs/AGENT-ORCHESTRATION.md`
- Create or modify: `test/eval-docs.test.js`

**Interfaces:**
Documentation must match the actual CLI flags, schema names, promotion thresholds, and privacy boundaries implemented above.

- [ ] **Step 1: Write a failing documentation contract test**

Test that both documents contain:

- `para11ax-eval-result-v1.0`;
- `para11ax-eval-scorecard-v1.0`;
- `npm run eval:verify`;
- explicit statement that v1 makes no model API calls;
- explicit statement that routing never auto-mutates from scorecards;
- exact default promotion thresholds `2%`, `3%`, `10%`, `15%` in the operator doc.

- [ ] **Step 2: Run red**

```bash
node --test test/eval-docs.test.js
```

Expected: FAIL until docs are written.

- [ ] **Step 3: Write `docs/PARA11AX-EVALS.md`**

Document:

1. purpose and trust boundary;
2. corpus/version/hash model;
3. candidate result schema and one sanitized example;
4. domain scoring summary;
5. hard failures vs weighted score;
6. exact promotion policy;
7. privacy and data-minimization boundary;
8. CLI commands and exit codes;
9. corpus update procedure: new version, regenerate hashes, update scorer version only when behavior changes;
10. routing-review procedure: compare exact same corpus/scorers, review human-review cases, then change routing explicitly in a separate reviewed source commit if justified.

- [ ] **Step 4: Link orchestration policy to internal eval evidence**

Add a short normative subsection to `docs/AGENT-ORCHESTRATION.md` stating that public benchmark changes do not directly alter routes and internal scorecard evidence is advisory input to a reviewed source change.

- [ ] **Step 5: Run green**

```bash
node --test test/eval-docs.test.js
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add docs/PARA11AX-EVALS.md docs/AGENT-ORCHESTRATION.md test/eval-docs.test.js
git commit -m "docs: define PARA11AX eval operations"
```

---

### Task 9: CI Integration and Full Repository Verification

**Files:**
- Modify: `package.json`
- Modify only if needed after inspection: `.github/workflows/tooling-smoke.yml`
- Test: entire repository

**Interfaces:**
`npm run check` becomes the authoritative local deterministic gate for eval self-tests plus corpus verification. Tooling smoke already calls `npm run check`, so prefer changing `package.json` rather than duplicating logic in the workflow.

- [ ] **Step 1: Write the intended package-script change**

Change `check` from:

```json
"check": "bash -n scripts/*.sh && npm run lint:shell && npm run verify:repo && npm run audit:public && npm test"
```

to:

```json
"check": "bash -n scripts/*.sh && npm run lint:shell && npm run verify:repo && npm run audit:public && npm test && npm run eval:verify"
```

Do not change `.github/workflows/tooling-smoke.yml` if it still invokes `npm run check`. Duplication would only give future humans two places to forget updating.

- [ ] **Step 2: Run the full deterministic suite locally**

```bash
npm ci --ignore-scripts
npm audit --omit=dev
npm run check
```

Expected: dependency audit has no blocking vulnerability and all checks pass.

- [ ] **Step 3: Prove the CLI has no network dependency by static import audit**

Run:

```bash
rg -n "from ['\"](node:https|node:http|https|http|undici|axios|got|openai|@anthropic)" src/eval scripts/run-evals.mjs
```

Expected: no matches.

- [ ] **Step 4: Run corpus/golden commands one final time**

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

- [ ] **Step 6: Open/update the feature PR and freeze the final head SHA**

PR title:

```text
Add deterministic PARA11AX internal eval harness
```

PR body must summarize:

- offline/no-provider-call architecture;
- nine-domain frozen corpus;
- deterministic scorecard/comparison;
- privacy-bounded aggregate outputs;
- explicit promotion gate;
- TDD evidence;
- completion rule: exact-head Tooling smoke + CodeQL success.

- [ ] **Step 7: Wait for exact-head CI and inspect failures by exact SHA**

Required workflows:

- `Tooling smoke`
- `CodeQL`

Do not merge based on earlier commits. If any test changes are needed, the head SHA changes and both workflows must be re-evaluated on the new final SHA.

- [ ] **Step 8: Squash merge only after both exact-head gates succeed**

Use repository-allowed squash merge with `expected_head_sha` pinned to the verified final feature head. Then verify:

1. PR state is `closed` and `merged=true`;
2. `main` points to the returned squash commit SHA;
3. the merged commit contains the eval harness files.

Expected final state: deterministic eval evidence is available from `main`, while production MCP/model routing behavior remains unchanged unless a future reviewed routing commit explicitly consumes the evidence.

---

## Self-Review Checklist

Before execution begins, the implementing agent must verify these plan invariants:

- Every spec deliverable maps to at least one task above.
- No task requires a live provider key or network request.
- No scorecard structure contains raw candidate output fields.
- Corpus hashing has one deterministic generation path and one independent verification path.
- The routing scorer imports production routing policy, while production routing imports nothing from `src/eval/`.
- Nullable measurements remain nullable through result validation, scorecard generation, and comparison.
- Promotion cannot be passed by weighted score if critical hard failures regress.
- Human-review-required cases block automatic promotion.
- Full-corpus-only behavior is enforced in v1.
- The existing Tooling smoke workflow remains authoritative through `npm run check`; avoid redundant workflow edits unless the workflow has changed before implementation.

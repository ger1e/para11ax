<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX Internal Eval Harness Design

Status: proposed architecture
Date: 2026-09-13
Branch: `feat/para11ax-eval-harness`

## 1. Purpose

PARA11AX now has deterministic mission state, handoff validation, context budgeting, model-routing policy, and a host-visible `executionPlan`. The missing measurement layer is an internal, reproducible way to evaluate whether a model/harness combination is actually good for PARA11AX work before routing guidance changes.

The eval system must answer questions such as:

- Does candidate A preserve provenance better than the current frontier route?
- Does candidate B generate valid KQL for the supported telemetry contract?
- Does a long-context candidate retain objective, constraints, decisions, and handoff state after reset?
- Is a more expensive model materially better on PARA11AX-specific workloads, or merely better on public generic benchmarks?
- Did a routing change improve quality without silently increasing unsupported claims, cost, or token use?

The harness is an offline evidence system. It does not call models itself in v1, does not mutate production routing automatically, and does not enter the deterministic MCP request path.

## 2. Goals

The implementation SHALL provide:

1. A versioned frozen corpus of representative PARA11AX tasks.
2. A provider-neutral candidate-result schema.
3. Deterministic schema validation and deterministic scoring.
4. Domain-specific metrics for CTI, provenance, classification, ATT&CK mapping, KQL contracts, handoff retention, context selection, routing behavior, and representative coding/review tasks.
5. Explicit separation between automatically scorable fields and fields requiring human review.
6. Aggregate scorecards with per-domain breakdowns, hard failures, quality metrics, token/cost/latency metadata, and reproducible hashes.
7. Candidate-vs-baseline comparison suitable for routing review.
8. Privacy controls so score summaries and telemetry never copy client names, IOCs, evidence bodies, raw model output, or other payload values.
9. A deterministic `npm run eval` command that evaluates supplied result bundles without credentials or network access.
10. Tests proving corpus validation, scoring determinism, privacy boundaries, and comparison behavior.

## 3. Non-goals

Version 1 SHALL NOT:

- call OpenAI, Anthropic, or any other model provider;
- store API credentials;
- use LLM-as-judge scoring;
- alter `src/core/model-routing.js` automatically;
- update routing based only on public benchmark rankings;
- execute arbitrary generated KQL against live customer tenants;
- contain real customer data, private incidents, internal credentials, or production IOCs;
- persist production routing telemetry;
- run expensive live model matrices in pull-request CI.

These are separate trust, cost, and governance decisions and require their own design review.

## 4. Architecture

The subsystem has four isolated layers.

### 4.1 Frozen corpus

Path: `evals/corpus/`

The corpus contains synthetic or sanitized cases only. Each case is immutable once released in a corpus version. Corrections create a new corpus version rather than silently rewriting historical test meaning.

Recommended layout:

```text
evals/
  corpus/
    v1/
      manifest.json
      cti/
      provenance/
      classification/
      attack/
      kql/
      handoff/
      context/
      routing/
      coding/
  fixtures/
    candidate-results/
```

`manifest.json` records:

- corpus schema version;
- corpus ID and version;
- release date;
- case IDs and domains;
- weights;
- expected scorer versions;
- SHA-256 of each case file;
- corpus-level hash over the canonical manifest and case hashes.

Each case uses a stable unique `caseId` and contains only the minimum material required to score that task. Human-readable prompts or evidence may exist in cases, but all content must be synthetic, public, or irreversibly sanitized.

### 4.2 Provider-neutral result bundle

A candidate run is imported as a result bundle rather than executed by PARA11AX.

Proposed top-level schema:

```json
{
  "schemaVersion": "para11ax-eval-result-v1.0",
  "corpusId": "para11ax-internal-v1",
  "runId": "operator-supplied-stable-id",
  "candidate": {
    "provider": "openai",
    "model": "example-model",
    "family": "example-family",
    "effort": "high",
    "harness": "chatgpt-host-v1",
    "harnessVersion": "..."
  },
  "measurements": {
    "inputTokens": 0,
    "outputTokens": 0,
    "costUsd": null,
    "latencyMs": null
  },
  "cases": [
    {
      "caseId": "cti-001",
      "output": {},
      "measurements": {}
    }
  ]
}
```

Unknown or unavailable measurements remain `null`; they are never converted to zero. Duplicate case IDs, unknown case IDs, malformed metadata, incompatible corpus IDs, or non-finite numeric values fail closed.

Raw candidate outputs are accepted only as evaluator input. They are never copied into aggregate telemetry or comparison summaries.

### 4.3 Deterministic scorers

Path: `src/eval/`

Suggested modules:

```text
src/eval/
  schemas.js
  corpus.js
  canonical.js
  score.js
  compare.js
  privacy.js
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
```

Each scorer is pure and deterministic: input case + candidate output -> normalized score object.

A scorer returns:

- `score`: numeric 0..1 only where deterministic grading is justified;
- `hardFail`: boolean for contract-breaking failures;
- `violations`: stable machine-readable codes;
- `metrics`: bounded scalar counts/ratios only;
- `humanReview`: explicit fields that cannot be graded safely by rules;
- `scorerVersion`.

No scorer infers intent from prose using fuzzy hidden heuristics. If a criterion cannot be robustly scored, it is reported as `humanReview.required=true` instead of fabricating mathematical certainty.

### 4.4 Scorecard and comparison

The evaluator produces a canonical scorecard:

```json
{
  "schemaVersion": "para11ax-eval-scorecard-v1.0",
  "corpus": {...},
  "candidate": {...},
  "aggregate": {
    "weightedScore": 0.0,
    "hardFailures": 0,
    "scoredCases": 0,
    "humanReviewCases": 0
  },
  "domains": {...},
  "measurements": {...},
  "scorecardHash": "sha256:..."
}
```

Comparison accepts a baseline scorecard and one or more candidate scorecards generated from the exact same corpus and scorer versions.

Comparison MUST reject mismatched corpus versions or scorer versions unless an explicit migration/comparison policy exists.

A candidate is never declared globally superior from weighted score alone. The comparison reports:

- weighted-score delta;
- hard-failure delta;
- per-domain deltas;
- provenance/unsupported-claim regressions;
- KQL contract regressions;
- cost/token/latency deltas where known;
- review requirements;
- whether the candidate satisfies a configurable promotion gate.

## 5. Initial corpus domains

### 5.1 CTI structured extraction

Measures deterministic extraction of explicitly present facts such as actor, malware, CVE, campaign, infrastructure type, dates, and source references.

Penalizes invented entities and unsupported relationships.

### 5.2 Provenance and unsupported claims

Cases provide a closed evidence set with stable evidence IDs. Candidate claims must cite those IDs.

Metrics include:

- supported-claim precision;
- missing-citation count;
- invalid-evidence-reference count;
- unsupported-claim count;
- contradiction count where the case encodes explicit contradictions.

Unsupported critical claims can trigger a hard failure.

### 5.3 IOC vs IOA/TTP classification

Uses explicit expected labels and allows only documented accepted equivalents. This catches common analytical category drift.

### 5.4 ATT&CK mapping

Cases use a bounded allowed technique/sub-technique set. Scoring measures precision and recall against expected mappings. Over-mapping is penalized rather than rewarded for producing a larger list.

### 5.5 KQL contract

Version 1 validates structural requirements, not execution against a live tenant.

Checks can include:

- permitted table set;
- forbidden dependencies such as Sysmon/watchlists when the case disallows them;
- required time bound;
- expected indicator fields;
- bounded joins/unions according to the case;
- required projection/aggregation properties;
- required metadata/header fields when the case asks for the PARA11AX hunting format;
- obvious syntax/contract patterns that the repository can deterministically validate.

If later execution validation is added, it must use a controlled synthetic schema/lab rather than production telemetry.

### 5.6 Handoff and constraint retention

Cases encode objective, constraints, accepted decisions, artifacts, and next actions, then evaluate a candidate continuation after simulated context reset.

Hard failures include silently changing a constraint, dropping a required accepted decision, or claiming completion with required next actions remaining.

### 5.7 Context selection

Cases contain prioritized context items with known token costs and required durable items. Candidate output lists selected IDs only.

Scoring verifies durable-state retention, budget compliance, and appropriate eviction of reproducible/scratch material.

### 5.8 Routing behavior

Cases encode task class, risk, complexity, context pressure, and failure count. Candidate routing decisions are compared with the normative routing contract.

This domain evaluates harness compliance with policy, not model intelligence.

### 5.9 Coding/review

Initial coding cases should be repository-shaped but compact: schema validation, reducer behavior, deterministic transformations, and review tasks with known defects.

The v1 scorer should emphasize observable contract results and fixture outputs, not subjective style.

## 6. Scoring and weights

Initial domain weights should reflect PARA11AX operational risk rather than case count. Proposed v1 weights:

- provenance / unsupported claims: 20%
- KQL contract: 15%
- CTI extraction: 15%
- handoff / constraint retention: 15%
- ATT&CK mapping: 10%
- IOC vs IOA/TTP classification: 10%
- context selection: 5%
- routing compliance: 5%
- coding/review: 5%

Weights live in the corpus manifest and therefore change only with a corpus-version change.

Hard failures are tracked separately from weighted score. A model with a higher aggregate score but a critical provenance or constraint-retention hard failure must not pass promotion by arithmetic averaging.

Recommended default promotion gate:

1. no new critical hard failures;
2. no regression greater than 2 percentage points in provenance or handoff retention;
3. no regression greater than 3 percentage points in KQL contract score;
4. weighted score improves by at least 2 percentage points OR materially reduces cost/token use with weighted score within 1 percentage point of baseline;
5. required human-review cases are completed before a routing recommendation is accepted.

These thresholds are configuration in the corpus/policy, not embedded throughout scorer code.

## 7. Privacy and data minimization

The eval harness must assume candidate output may contain sensitive-looking strings even though the official corpus is synthetic.

Aggregate scorecards SHALL NOT include:

- raw candidate output;
- raw prompt/evidence text;
- client names;
- IOCs or observable values;
- evidence bodies;
- generated KQL bodies;
- ServiceNow/report text;
- secrets or environment values.

Scorecards may contain stable case IDs, violation codes, scalar metrics, model metadata, token/cost/latency measurements, hashes, and reviewer status.

A privacy assertion test seeds marker strings into fixtures and proves those markers do not occur in scorecard or comparison serialization.

## 8. CLI and package contract

Add a deterministic CLI entry point, preferably `scripts/run-evals.mjs`, with no network access required.

Package scripts:

```json
{
  "eval": "node scripts/run-evals.mjs",
  "eval:verify": "node scripts/run-evals.mjs --verify-corpus"
}
```

Expected usage:

```text
npm run eval -- --results path/to/results.json
npm run eval -- --results candidate.json --baseline baseline.json
npm run eval:verify
```

Output defaults to concise human-readable text and supports canonical JSON output for automation.

Exit non-zero for malformed corpus, invalid result bundle, deterministic scoring failure, or failed explicit promotion gate. A merely lower candidate score should not fail unless comparison was invoked with a promotion requirement.

## 9. CI integration

Initial PR CI runs only deterministic self-tests and corpus verification. It does not call external model APIs.

Tooling smoke should eventually include:

- eval unit tests;
- corpus hash verification;
- golden scorecard reproduction from committed synthetic fixtures;
- privacy marker test.

A small committed golden candidate fixture ensures scorer changes are visible as test failures. Updating a golden score requires intentional review of the scorer/corpus version, not casual snapshot regeneration.

## 10. Versioning and reproducibility

Version independently:

- corpus schema;
- corpus release;
- result schema;
- scorecard schema;
- each domain scorer.

Every scorecard records all relevant versions and hashes. A result is reproducible only if the corpus, scorer versions, evaluator code revision, and candidate result bundle are known.

Canonical JSON serialization must use stable key ordering before hashing. Floating-point outputs should be normalized to a documented precision to avoid cross-runtime noise.

## 11. Error handling

Fail closed on:

- unknown schema versions;
- duplicate IDs;
- missing corpus cases required by the selected evaluation profile;
- corpus/hash mismatch;
- result/corpus mismatch;
- NaN/Infinity/negative token or latency values;
- invalid score ranges;
- scorer exceptions;
- privacy-policy violations in generated scorecards.

Human-review-required is not an error. It is an explicit incomplete state that blocks automatic promotion when the promotion policy requires that review.

## 12. Testing strategy

Implementation follows TDD. Required regression coverage includes:

1. corpus manifest validates and hashes reproduce exactly;
2. corpus mutation breaks verification;
3. duplicate/unknown case IDs are rejected;
4. result metadata validation rejects malformed measurements;
5. each domain scorer has positive, partial, and hard-failure fixtures;
6. unsupported claims and invalid provenance references are penalized deterministically;
7. ATT&CK over-mapping lowers precision;
8. KQL forbidden dependencies and missing required structure are detected;
9. handoff constraint loss triggers hard failure;
10. context budget violation and durable-item loss are detected;
11. routing cases match the normative policy contract;
12. same input produces byte-identical canonical scorecard JSON and hash;
13. result ordering does not change the scorecard;
14. scorecard contains none of the seeded privacy markers;
15. comparison rejects incompatible corpus/scorer versions;
16. promotion gate cannot be passed by weighted score when a critical hard failure regresses;
17. missing cost/latency stays `null` and never becomes zero;
18. CLI exit codes distinguish invalid input from valid-but-not-promoted candidates.

## 13. Integration with current orchestration

`src/core/model-routing.js` remains the normative deterministic routing policy.

The eval harness does not import production customer state or write to Mission workspaces. It may import routing helpers to test policy compliance, but it must not create a circular dependency where production routing depends on eval scorecards at runtime.

Routing updates remain reviewed source changes. A future operator may use a scorecard comparison as evidence for such a change, but the act of changing the mapping remains explicit and auditable.

The existing MCP `executionPlan.telemetry` remains ephemeral aggregate metadata. The eval subsystem uses its own offline run/result/scorecard contracts; production telemetry persistence is deliberately outside this design.

## 14. Deliverables

The implementation phase should produce, at minimum:

- `evals/corpus/v1/manifest.json` and an initial compact synthetic corpus;
- `src/eval/` schemas, canonicalization, validation, scorers, comparison, and privacy guard;
- `scripts/run-evals.mjs`;
- `test/eval-*.test.js` coverage;
- synthetic golden candidate/result fixtures;
- package scripts;
- `docs/PARA11AX-EVALS.md` operator documentation;
- updates to `docs/AGENT-ORCHESTRATION.md` linking routing review to internal eval evidence.

## 15. Completion criteria

The subsystem is complete when:

1. the frozen corpus verifies against its manifest and hashes;
2. the evaluator runs without network access or credentials;
3. committed golden fixtures reproduce byte-identical scorecards;
4. privacy-marker tests prove aggregate outputs do not copy payload values;
5. all domain scorers have deterministic regression coverage;
6. baseline/candidate comparison enforces version compatibility and hard-failure gates;
7. `npm run eval` and `npm run eval:verify` are documented and pass;
8. repository Tooling smoke and CodeQL pass on the exact final feature head;
9. routing behavior in production remains unchanged unless a separate reviewed change explicitly updates it.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

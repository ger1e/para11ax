<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX Internal Evaluation Harness

Status: normative operator contract for offline internal evaluation
Runtime boundary: offline evaluator only

PARA11AX eval v1 is a deterministic, provider-neutral evidence harness for comparing candidate model/harness outputs against a frozen synthetic corpus. It does not call model APIs, provider APIs, or the production MCP path. There are no model API calls in v1, no LLM-as-judge scoring, and no automatic routing mutation.

The evaluator accepts local result bundles using `para11ax-eval-result-v1.0` and emits aggregate-only `para11ax-eval-scorecard-v1.0` scorecards. Candidate outputs are input to scoring only. They are not copied into scorecards or comparisons.

## 1. Trust boundary

The evaluator is advisory infrastructure, not a production decision engine. `src/core/model-routing.js` remains the normative runtime routing policy. Eval results may justify a separately reviewed source change, but the evaluator never automatically mutates production routing.

The v1 trust rules are:

- no model-provider API calls, network access, credentials, or production egress;
- no production customer data, private incidents, credentials, or production IOCs in the committed corpus or fixtures;
- only synthetic or public-reserved material is committed;
- full-corpus evaluation only;
- candidate outputs stay outside aggregate scorecards;
- missing cost or latency remains `null`, never zero;
- human review is explicit and promotion-blocking when required.

## 2. Corpus and reproducibility

The canonical corpus is `evals/corpus/v1/`. Its manifest uses `para11ax-eval-corpus-manifest-v1.0` and records corpus identity/version, case paths and SHA-256 hashes, domain weights, scorer versions, and promotion policy.

Each case is validated as `para11ax-eval-case-v1.0`. Case hashes use canonical JSON with recursively sorted object keys while preserving order-significant arrays. The manifest `corpusHash` binds the complete case set and policy. A changed case, scorer version, domain weight, or promotion rule therefore creates different evaluation evidence rather than silently masquerading as the previous corpus.

A valid scorecard records corpus ID/version/hash, scorer versions, evaluator version, result hash, aggregate/domain metrics, bounded review state, measurements, and its own deterministic scorecard hash.

## 3. Candidate and review contract

A candidate result bundle records provider, model, family, effort, harness, harness version, aggregate token/cost/latency measurements, and exactly one result per corpus case. Case output can be rich because it is evaluator input, but it is never an allowed scorecard payload field.

Human review is either absent, pending, or completed with an explicit `pass`/`fail` decision. Reviewer prose is not copied into scorecards. Any required review that is pending or failed blocks promotion.

## 4. Domains and scoring

The frozen v1 corpus covers nine domains: CTI extraction, provenance, IOC/IOA/TTP classification, ATT&CK mapping, KQL structure, durable handoff, context selection, routing-policy compliance, and coding/review defect identification.

Important deterministic rules include:

- provenance score is required-claim recall multiplied by citation precision; critical unsupported claims hard-fail;
- ATT&CK and coding/review use precision/recall-style scoring so over-reporting is penalized;
- KQL checks required tables/headers/patterns and hard-fails forbidden dependencies;
- handoff hard-fails objective drift, lost constraints/accepted decisions, and premature completion;
- context score is 70% durable retention plus 30% eviction quality; durable loss, unknown IDs, and budget overflow hard-fail;
- routing is scored against the live normative `routeModelTask()` policy across tier, effort, context policy, independent review, and different-family review; omission of required independent review hard-fails.

A weighted score does not erase hard failures. Promotion evaluates both scalar quality and explicit blocking conditions.

## 5. Manifest-driven promotion policy

The manifest is the single runtime source of promotion thresholds. The approved v1 thresholds are:

- Provenance maximum regression: 2%.
- Handoff maximum regression: 2%.
- KQL maximum regression: 3%.
- Weighted score minimum improvement: 2%.
- Weighted efficiency tolerance: 1% below the baseline score.
- Efficiency reduction requirement: 20% or more in known total-token use or known cost.

Promotion also requires no increase in critical hard failures and every required human review to be completed with `pass`.

A candidate passes by either improving weighted quality by at least 2%, or remaining within the 1% weighted efficiency tolerance while reducing a known efficiency measure by at least 20%. Unknown cost/latency values remain unknown and cannot manufacture an efficiency win.

## 6. Privacy boundary

`src/eval/privacy.js` rejects payload-bearing scorecard keys such as output, query, body, evidence, prompt, content, indicator, observable, client names, ServiceNow payloads, or raw values. Case-result strings are restricted to stable IDs/codes, bounded review state, domains, and scorer versions. Metrics are scalar or explicitly bounded symbolic values.

The committed baseline fixture deliberately contains a distinctive private marker in raw candidate output. Tests prove that marker does not survive scorecard or comparison serialization.

## 7. CLI

Verify the committed corpus:

```text
npm run eval:verify
```

Score one candidate:

```text
npm run eval -- --results <file>
npm run eval -- --results <file> --json
```

Compare a candidate against a baseline:

```text
npm run eval -- --results <candidate> --baseline <baseline>
npm run eval -- --results <candidate> --baseline <baseline> --require-promotion
```

CLI outcomes are explicit: exit code 0 means valid evaluation/comparison; exit code 2 means invalid arguments, input, or corpus; exit code 3 means the comparison was valid but a required promotion gate failed.

The CLI reads local UTF-8 JSON only. Human-readable output may show candidate metadata, hashes, aggregate/domain scores, scalar measurements, violation counts, review state, and promotion reason codes. It must never print raw case output.

## 8. Corpus versioning

Do not edit a released corpus case or policy and keep the same evidence identity. For a meaningful corpus change:

1. update or add only synthetic/public-safe cases;
2. update scorer versions when scorer semantics change;
3. regenerate case hashes and `corpusHash` through the implementation rather than by hand;
4. bump corpus version when comparability changes;
5. rerun `npm run eval:verify` and full repository tests;
6. establish a reviewed baseline on the new corpus before using promotion evidence.

Cross-corpus, cross-scorer, cross-evaluator, or cross-policy scorecards are incompatible by design.

## 9. Routing review procedure

Public benchmark rankings are priors, not routing authority. Internal eval evidence is stronger for PARA11AX-specific CTI/KQL/handoff workloads, but it remains advisory. A routing change requires human review of the candidate scorecard/comparison, model availability, harness configuration, cost/latency evidence, and security implications, followed by a normal source change to `src/core/model-routing.js` and its tests.

Production routing has no runtime dependency on eval results. The evaluator imports production routing for the routing-domain oracle; production routing never imports the evaluator.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

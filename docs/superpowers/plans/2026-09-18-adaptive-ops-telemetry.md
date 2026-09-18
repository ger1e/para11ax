# Adaptive Operations Telemetry Implementation Plan

Date: 2026-09-18
Design: `docs/superpowers/specs/2026-09-18-adaptive-ops-telemetry-design.md`
Branch: `feat/adaptive-ops-telemetry`

## Acceptance criteria

- Request-local telemetry is bounded and fail-safe.
- Unknown and sensitive fields never appear in captured events or summaries.
- Existing provider execution behavior is unchanged.
- Provider-family metadata is derived from `config/providers.json`, not hard-coded per-provider duplication.
- Regression fixtures include positive, negative, FP, boundary and missing-telemetry cases.
- Missing required telemetry maps to `CANNOT OBSERVE`, never a clean verdict.
- No external observability SDK is added.
- Required GitHub `Tooling smoke` passes before merge.

## Task 1: Telemetry contract, RED

Files:
- create `test/core-telemetry.test.js`

Write tests importing `createRequestTelemetry` from `src/core/telemetry.js`. Cover:
1. safe event allowlist
2. stripping `taskId`, `indicator`, `credentials`, `headers`, `authorization`, `payload`, `requestBody`, `responseBody`
3. deterministic timestamp injection
4. event cap and dropped-event count
5. fail-safe invalid event input
6. aggregate attempt/success/failure/retry/duration summary

Commit the failing tests and verify `Tooling smoke` fails for the expected missing module only.

## Task 2: Telemetry implementation, GREEN

Files:
- create `src/core/telemetry.js`

Implement bounded request-local collection and summary aggregation. Do not change provider-runner semantics. Run the telemetry tests, then the full required smoke workflow.

## Task 3: Provider-runner integration regression

Files:
- create `test/provider-runner-telemetry.test.js` or extend the existing provider-runner test if present

Use a fake provider/task/budget and the real collector. Assert:
- emitted events are accepted by the collector
- summary reflects attempts and result
- task identifiers and synthetic IOC/payload fields never survive collection
- telemetry exceptions cannot break provider execution

## Task 4: Provider-family QA derivation

Files:
- create `src/eval/provider-qa.js`
- create `test/provider-family-qa.test.js`

Derive family grouping from `config/providers.json` using `providerFamily ?? id`. Return safe family metadata only. Assert the current upstream source-family count is 39 and family variants such as Censys search/history collapse into the Censys family.

Do not hard-code 39 in implementation logic. The test pins the current contract intentionally so source-count changes require review.

## Task 5: Detection regression fixtures

Files:
- create `test/fixtures/detection-regression/cases.json`
- create `test/detection-regression-fixtures.test.js`

Seed generic controlled cases:
- positive suspicious device-code / cloud-collection chain
- negative legitimate interactive admin activity
- FP legitimate RMM/admin overlap
- boundary browser ClickFix-style script execution
- telemetry-missing case requiring `CANNOT OBSERVE`

Validate fixture schema, unique IDs, allowed result classes and privacy-safe content.

## Task 6: Documentation and observability gate

Files:
- update relevant architecture/operations documentation only if an existing section owns runtime telemetry

Document that internal bounded telemetry is authoritative for the current observability decision. External vendor tooling remains deferred until measured production needs clear the integration admission threshold.

## Task 7: Verification and integration

1. Run branch `Tooling smoke` and inspect jobs/steps.
2. Review PR diff for privacy leakage, unrelated refactors and duplicated evaluation machinery.
3. Confirm no vendor observability dependency was added.
4. Confirm source-family contract remains 39 on current manifest.
5. Squash merge only after required checks pass.
6. Re-fetch main and verify the merged revision.

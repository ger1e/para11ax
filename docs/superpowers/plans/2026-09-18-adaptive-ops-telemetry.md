<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md), [docs/OPERATIONS.md](https://github.com/ger1e/para11ax/blob/main/docs/OPERATIONS.md), and the current README.

# Adaptive Operations Measurement Implementation Plan

Date: 2026-09-18
Design: `docs/superpowers/specs/2026-09-18-adaptive-ops-telemetry-design.md`
Branch: `feat/adaptive-ops-telemetry`

## Acceptance criteria

- Existing `createTelemetry()` remains the canonical runtime telemetry contract.
- Existing privacy properties remain covered: allowlisted fields, aggregate stats, indicator-off by default, sink failures non-fatal.
- Provider-family metadata is derived from `config/providers.json`, not manually duplicated.
- Current manifest resolves to 39 unique upstream source families.
- Regression fixtures cover positive, negative, FP, boundary and missing-telemetry cases.
- Missing required telemetry maps to `CANNOT OBSERVE`, never a clean verdict.
- No external observability SDK is added.
- Required GitHub `Tooling smoke` and CodeQL pass before merge.

## Discovery correction

The first RED test assumed a new collector API. CI proved that assumption wrong: `src/core/telemetry.js` already exists and existing tests already enforce its privacy/aggregation contract. The implementation therefore extends the existing architecture rather than replacing or duplicating it.

## Task 1: Preserve existing telemetry contract

Files:
- existing `src/core/telemetry.js`
- existing `test/telemetry.test.js`

No new collector is required. Keep the existing allowlist/aggregate behavior and use it as the runtime measurement substrate. Any future telemetry extension must preserve its privacy boundary and fail-safe sink behavior.

## Task 2: Provider-family QA, RED → GREEN

Files:
- create `test/provider-family-qa.test.js`
- create `src/eval/provider-qa.js`

RED assertions:
1. manifest-derived unique source-family count is 39;
2. every provider belongs to exactly one family via `providerFamily ?? id`;
3. Censys search/history collapse into `censys`;
4. safe projection contains no credential environment variable names, hosts or secret values;
5. output is deterministic under manifest key-order changes.

GREEN implementation:
- pure function accepting a manifest object;
- family, member IDs, types, source roles, freshness classes, credential posture and active-state projection only;
- no file/network access inside the helper.

## Task 3: Detection regression fixtures, RED → GREEN

Files:
- create `test/detection-regression-fixtures.test.js`
- create `test/fixtures/detection-regression/cases.json`

RED assertions:
- unique fixture IDs;
- exact allowed case classes: positive, negative, fp, boundary, telemetry_missing;
- exact allowed outcomes including `CANNOT_OBSERVE`;
- required telemetry declared per case;
- no client-specific or secret-shaped fields;
- telemetry-missing case must expect `CANNOT_OBSERVE`.

GREEN corpus:
- suspicious device-code/cloud collection positive case;
- legitimate interactive-admin negative case;
- legitimate RMM/admin overlap FP case;
- browser-resident ClickFix/userscript boundary case;
- missing-browser/identity/network telemetry case.

## Task 4: Gergő Ops normalized measurement state

Airtable tables created during this program:
- Workflow Telemetry
- Provider QA
- Detection Regression Cases

Populate only safe normalized state. GitHub remains executable source of truth. Do not copy raw client evidence, credentials, identities or indicators.

## Task 5: Documentation and observability gate

Update current operations/architecture documentation only where it owns runtime measurement semantics. Record that internal bounded telemetry and offline eval are sufficient today. External observability remains deferred until measured needs clear the existing integration admission threshold.

## Task 6: Verification and integration

1. Run branch `Tooling smoke` and CodeQL.
2. Inspect failures, jobs and logs rather than trusting status labels alone.
3. Review PR diff for privacy leakage, unrelated refactors and duplicated eval/telemetry machinery.
4. Confirm no vendor observability dependency was added.
5. Confirm current source-family contract remains 39.
6. Squash merge only after required checks pass.
7. Re-fetch protected main and verify the merged revision and current documentation.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md), [docs/OPERATIONS.md](https://github.com/ger1e/para11ax/blob/main/docs/OPERATIONS.md), and the current README.

# Adaptive Operations Measurement Design

Date: 2026-09-18
Status: approved program scope

## Purpose

Extend PARA11AX's existing privacy-safe telemetry and evaluation seams with source-family QA and reusable detection-regression evidence. Do not add a second telemetry framework or a vendor observability SDK.

Repository discovery during the RED phase established that `src/core/telemetry.js` already provides an allowlisted, aggregate-only `createTelemetry()` contract, `src/core/provider-runner.js` emits bounded provider completion telemetry, and `src/eval/` already owns offline evaluation/regression logic. Those are the implementation seams.

GitHub remains implementation authority. Airtable stores only normalized operational measurements and lifecycle state.

## Goals

1. Preserve and regression-test the existing telemetry privacy boundary.
2. Derive canonical provider-source-family QA from `config/providers.json` using `providerFamily ?? providerId`.
3. Prevent graph/search/history variants from inflating the 39-source-family count.
4. Add generic detection/hunt regression fixtures for positive, negative, false-positive, boundary and missing-telemetry semantics.
5. Represent missing required telemetry as `CANNOT OBSERVE`, never as clean/benign evidence.
6. Keep external observability products behind a measured admission gate.

## Non-goals

- No new telemetry collector API.
- No persistent production event store in this change.
- No PostHog, Datadog, Sentry or other vendor SDK.
- No raw IOC, request body, credential, header, provider payload or client evidence persistence.
- No replacement for `src/eval/`.
- No routing-policy change to frozen Adaptive V3 merely because measurement improves.

## Existing runtime telemetry

`createTelemetry()` is the canonical runtime substrate. It already:

- allowlists bounded operational fields;
- strips raw indicators by default and arbitrary secret-bearing keys;
- isolates sink failures from enrichment execution;
- exposes aggregate event/provider/status/outcome counts;
- keeps provider-outcome categories bounded;
- supports indicator inclusion only through explicit local debug mode.

This change must reuse that contract rather than introduce competing event semantics.

## Provider-family QA

Add a pure eval helper that consumes the provider manifest and returns safe normalized family metadata:

- family key;
- member provider IDs;
- supported observable types;
- source roles;
- freshness classes;
- credential posture;
- active/disabled state.

Family identity is `policy.providerFamily ?? providerId`. The implementation must derive counts from the manifest. Tests intentionally pin the current contract at 39 unique upstream source families so a future count change requires review.

Variant capabilities such as Censys search/history and VirusTotal/urlscan graph functions must not become independent source families unless the manifest explicitly defines them that way.

## Detection regression fixtures

Add public/generic controlled fixtures under `test/fixtures/detection-regression/` covering:

- positive malicious behavior;
- negative benign/admin behavior;
- false-positive overlap with legitimate RMM/admin activity;
- browser-resident ClickFix/userscript boundary behavior;
- missing required telemetry with expected `CANNOT_OBSERVE`.

Fixtures define scenario, expected telemetry and expected analytical result. They contain no client names, internal hosts, users, incident evidence or customer-specific indicators.

## Gergő Ops measurement planes

Airtable owns three normalized operational tables created in this program:

- `Workflow Telemetry` for route/outcome/stop-state metadata;
- `Provider QA` for source-family health/coverage metadata;
- `Detection Regression Cases` for fixture lifecycle metadata.

Client-restricted content may influence an authorized runtime analysis but raw restricted material must not be copied into these personal operational tables.

## Error and uncertainty semantics

Measurement must never change provider execution semantics. Failures in measurement remain non-fatal to the investigated workflow. Provider absence, missing credentials, unavailable telemetry or unexecuted surfaces are represented as coverage state, not negative threat evidence.

A zero-result with required telemetry missing is `CANNOT OBSERVE`, never `CLEAN`.

## Testing

TDD sequence after repository discovery:

1. Provider-family QA test fails because `src/eval/provider-qa.js` does not exist.
2. Implement the smallest pure manifest-derived helper until green.
3. Detection-regression schema test fails because the controlled fixture corpus does not exist.
4. Add the minimum privacy-safe fixture corpus until green.
5. Retain existing telemetry tests as the runtime privacy/aggregation regression contract.
6. Run required `Tooling smoke` and CodeQL on the branch.

## Observability admission gate

The current internal telemetry + eval subsystem is the measurement substrate. External observability tooling is admitted only after production measurements identify an unresolved dimension the internal substrate cannot economically supply, such as distributed tracing across multiple services, sustained failure diagnosis, long-retention querying or user/product analytics with a concrete decision owner.

The normal integration gate remains approximately 2% unique decision gain plus a distinct evidence/action plane. Until that evidence exists, adding a vendor SDK would increase attack surface and operational entropy without demonstrated value.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

# Adaptive Operations Telemetry Design

Date: 2026-09-18
Status: approved program scope

## Purpose

Add bounded, privacy-safe execution telemetry and regression evidence to PARA11AX without introducing a vendor observability dependency or a second evaluation framework.

The design extends existing seams: `src/core/provider-runner.js` already emits `scheduler.provider_attempt` events and `src/eval/` already owns evaluation/regression logic. GitHub remains implementation authority; Airtable stores only normalized operational measurements.

## Goals

1. Measure provider execution quality: attempts, outcomes, retries, latency and source-family coverage.
2. Measure workflow efficiency without storing raw indicators, request bodies, credentials, headers, tokens or client evidence.
3. Expose deterministic summaries suitable for regression tests and later export.
4. Derive provider-family QA from the canonical manifest rather than hand-maintained counts.
5. Add controlled detection/hunt regression fixtures for positive, negative, false-positive, boundary and missing-telemetry cases.
6. Keep external observability products behind an evidence gate until internal telemetry proves a need.

## Non-goals

- No persistent production event store in this change.
- No PostHog, Datadog, Sentry or other vendor SDK.
- No raw IOC or client telemetry persistence.
- No replacement for the existing `src/eval/` subsystem.
- No change to the frozen Adaptive V3 routing policy merely because telemetry is added.

## Architecture

### Request-local telemetry collector

Add `src/core/telemetry.js` with a bounded collector interface:

```js
const telemetry = createRequestTelemetry({ maxEvents: 256, now: Date.now });
telemetry.emit(name, fields);
telemetry.events();
telemetry.snapshot();
```

The collector accepts only an explicit allowlist of safe fields. Unknown keys and sensitive fields are discarded. It never serializes indicators, task IDs, credentials, request bodies, headers, authorization material or provider payloads.

The event buffer is bounded. After the cap, later events increment a dropped-event counter rather than increasing memory use.

### Existing provider-runner integration

`executeProviderTask` continues to emit its existing `scheduler.provider_attempt` events. The new collector consumes them without requiring provider implementations to change.

Summary output includes only safe aggregates:

- event count and dropped-event count
- provider/source-family names
- attempt count
- success/failure/retry counts
- status/outcome counts
- total and maximum provider duration
- bounded budget snapshots where numeric

No summary field contains the queried indicator or response data.

### Provider-family QA

The canonical source-family count is derived from `config/providers.json` using `providerFamily ?? providerId`. Tests assert that:

- every active provider has a source family
- the derived family count matches user-facing registry count
- family grouping does not double-count search/history/graph variants
- disabled providers cannot silently appear healthy

A report helper returns safe metadata only: family, provider IDs, supported observable types, source roles, freshness classes, credential requirement and active state.

### Detection regression fixtures

Add public/generic fixtures under `test/fixtures/detection-regression/`. Cases cover positive malicious behavior, negative benign behavior, false-positive overlap, boundary behavior and missing telemetry where the correct result is `CANNOT OBSERVE`.

Fixtures describe expected telemetry and expected analytical result. They contain no client names, internal hosts, users or incident evidence.

## Security and privacy

Telemetry follows an allowlist, not a denylist. Sensitive or unknown fields are dropped by construction. The collector is request-local and non-persistent. Export or persistence is a separate future decision requiring its own privacy review.

Client-restricted material may influence an in-memory workflow, but only minimum normalized state may leave the authorized environment. A zero-result with missing required telemetry is represented as `CANNOT OBSERVE`, never `CLEAN`.

## Error handling

Telemetry must never change provider execution semantics. `emit()` is fail-safe and must not throw into provider execution. Invalid event names or non-object fields are ignored. Snapshot generation is deterministic and side-effect free.

## Testing

TDD sequence:

1. Unit tests fail because `src/core/telemetry.js` does not exist.
2. Implement collector until unit tests pass.
3. Add provider-runner integration test proving sensitive fields are absent from captured events and summaries.
4. Add provider-family manifest tests.
5. Add fixture schema and regression tests.
6. Run required `Tooling smoke` workflow on the branch.

Tests cover event cap, allowlisting, sensitive-field stripping, deterministic clocks, aggregation, provider variants and `CANNOT OBSERVE` fixture semantics.

## Observability admission gate

Internal telemetry is the measurement substrate. An external observability product is admitted only if real measurements show at least one unresolved dimension that the internal substrate cannot economically provide, such as sustained production failure diagnosis, distributed tracing across external services, or retention/query requirements. The normal integration admission threshold remains approximately 2% unique decision gain plus a distinct evidence/action plane.

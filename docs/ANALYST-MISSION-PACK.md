<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# Analyst Mission Pack v1

Analyst Mission Pack v1 is a deterministic, local analysis layer that converts explicit environment context into an auditable hunt package and bounded downstream analyst output. It is additive to Evidence v2, the Intelligence Kernel, Decision Support, Guidance, Evidence Graph, local cases, and the existing report compiler.

It does not add a model call, provider, network destination, secret, persistence mechanism, automatic detection deployment, or automatic ServiceNow submission.

## Workflow

```text
explicit client profile
  -> relevance assessment
  -> hunt package
  -> conservative KQL validation
  -> analyst executes query outside this module
  -> bounded JSON/CSV result analysis
  -> ServiceNow-ready projection
```

The mission layer never upgrades imported result rows or specialist operator records into Evidence v2 and never treats an empty result set as proof of benign state.

## Public mission core

`src/core/mission/index.js` exports exactly five pure functions:

- `normalizeClientProfile(input)`
- `assessClientRelevance(profile, context)`
- `validateMissionKql(query)`
- `buildHuntPackage(input)`
- `analyzeMissionResults(input)`

ServiceNow projection remains a report-layer concern under `src/report/render-servicenow.js`.

## ClientProfile v1

A client profile contains only explicit caller-provided environment facts:

- `id`, `name`
- `industries[]`
- `geographies[]`
- `technologies[]`
- `attackPaths[]`
- `priorityActors[]`
- `telemetry[]`
- `crownJewels[]`

Lists are bounded to 64 items, normalized, deduplicated, sorted, and frozen. The mission layer does not persist profiles server-side.

## RelevanceAssessment v1

Relevance is an operational-fit index. It is not maliciousness, compromise probability, attribution confidence, or incident severity.

The fixed 100-point model exposes every contribution:

| Factor | Weight |
|---|---:|
| technology overlap | 25 |
| observed exploitation | 20 |
| industry overlap | 15 |
| geography overlap | 10 |
| attack-path overlap | 10 |
| actor overlap | 10 |
| telemetry huntability | 5 |
| evidence confidence | 5 |

Unknown factors contribute zero and appear in `gaps[]`. Labels are `immediate`, `high`, `moderate`, `low`, and `contextual`; they describe relevance only.

## HuntPackage v1

A hunt package contains a deterministic content-derived `HNT-` identifier, hypothesis, subject, ATT&CK technique IDs, required/available telemetry, telemetry gaps, evidence fingerprints, source references, relevance, KQL candidates, and limitations.

State fails closed in this order:

1. `INSUFFICIENT_EVIDENCE` when defensible provenance is absent.
2. `TELEMETRY_GAP` when required telemetry is unspecified or unavailable.
3. `SCHEMA_UNVERIFIED` when included KQL cannot be validated against the local schema contract.
4. `READY` only when those gates pass.

Evidence fingerprints must be 64-character hexadecimal SHA-256 values. Source references must be bounded HTTP(S) URLs without embedded credentials. ATT&CK identifiers are technique/sub-technique IDs only.

## KQL validation

`validateMissionKql` is a conservative static guardrail, not a Microsoft tenant compiler.

The local catalog covers the Defender XDR/Sentinel tables PARA11AX currently targets, including endpoint, identity, email, Entra sign-in, and Windows security telemetry. The validator:

- rejects empty queries and queries over 32,000 characters;
- rejects Kusto control/query-management commands;
- validates referenced tables against the bounded local catalog;
- validates deterministically extractable `where` and `project` columns;
- marks unknown tables or columns `SCHEMA_UNVERIFIED`;
- marks `search *` and wildcard `union *` as unbounded/unverified;
- never executes KQL.

Unknown schema is not guessed.

## Result analysis

`analyzeMissionResults` accepts flat JSON rows or CSV and performs no network activity.

Hard bounds:

- maximum encoded input: 2 MiB;
- maximum rows: 5,000;
- maximum columns: 128;
- maximum field length: 4,096 characters;
- JSON rows must contain only strings, numbers, booleans, or null.

States are `RESULTS_PRESENT`, `NO_RESULTS`, and `IMPORT_EMPTY`; malformed or oversized input fails closed. Formula-like spreadsheet strings are counted but remain inert strings. `NO_RESULTS` always carries `no_results_is_not_benign_evidence`.

## ServiceNow projection

`buildServiceNowProjection` and `renderServiceNowText` create deterministic ticket-ready output containing client context, hunt/result state, ATT&CK, evidence references, telemetry gaps, KQL validation state, limitations, and recommended analyst actions.

The suggested priority is derived only from client relevance and is explicitly labeled `client_relevance_only_not_incident_severity`. The renderer never assigns automatic P1, sends a request, reads secrets, or creates a ticket. Human approval remains mandatory before escalation or submission.

## Mission Workspace v1

`src/core/mission/workspace.js` composes the pure mission functions into a portable `mission-workspace-v1.0` bundle. The bundle carries the normalized profile, normalized context, relevance assessment, hunt package, up to eight KQL validations, imported result summary and ServiceNow-ready projection. A monotonic revision records successful workspace transitions.

The shared command adapter exposes the same twelve commands to Web and CLI:

```text
mission new
mission show
mission profile set '<json>'
mission context set '<json>'
mission relevance
mission hunt build '<json>'
mission kql validate '<query>'
mission result analyze
mission servicenow
mission export
mission import
mission clear
```

Profile or context changes invalidate every dependent projection. Rebuilding a hunt invalidates prior result and ServiceNow output. Failed transitions are atomic and leave the current frozen workspace unchanged.

Export is canonical JSON with a trailing newline. Import validates the complete JSON tree, accepts only the exact schema, reconstructs every derived projection from authoritative inputs, and rejects tampering rather than trusting serialized scores, states or ticket fields. The bundle contains data only; it never carries authentication state, runtime handles or secrets.

### Transport and lifetime

- **Web:** workspace state is memory-only. File import uses an explicit bounded picker. `mission export | download` is the sole browser write. `disconnect` and `reboot` clear mission state; `auth clear` preserves it.
- **CLI:** state lives only for the current PARA11AX pipeline/process. Content may be supplied inline, by exact `--file <path>`, or by exact `--stdin`. Stdin is not consumed implicitly.
- **Both:** each content transport is capped at 2 MiB and routes through the same command adapter and reducer.

KQL validation does not query a Microsoft tenant. Result analysis does not execute a query. ServiceNow projection does not submit a ticket. Those operations remain analyst-controlled external actions.

## Investigation v2 adoption

Mission Workspace v1 remains a compatible standalone, volatile workflow for one migration release. Investigation Workspace v2 is the canonical persistent analyst lifecycle. A validated Mission Workspace bundle may be explicitly adopted into an active investigation: authoritative profile/context inputs are retained after conflict checks, while relevance, hunt, KQL validation, result analysis, and ServiceNow projection are validated/reconstructed rather than blindly trusted.

Existing compatible case v1.0 records migrate in memory on first Investigation v2 access. Identity, title, timestamps, pins, notes, Evidence v2 snapshots, and semantic diffs are preserved within Investigation v2 bounds. Oversized legacy cases fail closed without truncation or replacement.

Investigation v2 also owns a separate **operator context** authority layer. Compatible User Scanner, Shodan, and GreyNoise Project Swarm read results can be explicitly captured with `investigation capture operator`. This does not convert them into Evidence v2 or mission result rows. In particular, `swarm search`, `swarm get`, `swarm unique`, and `swarm timeseries` can provide contextual investigation material; `swarm export` PCAP/raw downloads remain outside automatic capture. See `GREYNOISE-SWARM.md` and `SHELL.md`.

Mission relevance and hunt construction must continue to distinguish authoritative Evidence v2 fingerprints from contextual operator material. If operator context informs analyst reasoning, the resulting hypothesis/limitations should say so explicitly rather than inventing provider corroboration.

## Security boundary

Mission v1 adds no runtime dependency and no egress. It contains no `fetch`, provider execution, secret access, dynamic evaluation, child-process execution, file write, or server-side persistence path. Existing Evidence v2 and Intelligence Kernel semantics remain authoritative; mission objects are downstream analyst-support projections. GreyNoise Swarm, Shodan and User Scanner remain separate bounded operator routes and do not expand Mission Workspace egress.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
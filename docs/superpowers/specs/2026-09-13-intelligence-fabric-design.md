<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Architecture approved in chat; written specification pending final user review. Current production behavior remains authoritative until this design is implemented, reviewed, merged, deployed, and verified.

# PARA11AX Intelligence Fabric Design

Date: 2026-09-13
Status: architecture approved; written spec pending review
Base commit: `dc1445b0596bda6833ae1c2fe6cf78b16ce4bcc5`
Branch: `intelligence-fabric-20260913`

## Objective

Expand PARA11AX from a flat IOC-enrichment gateway into a policy-governed multi-lane CTI and OSINT intelligence fabric. The goal is broader evidence classes and deeper provider relationships without turning every lookup into an unbounded fan-out across every configured service.

The system must preserve deterministic classification, Evidence v2 provenance, fixed-host egress, bounded execution, partial-failure semantics, quota awareness, export controls, branch protection, and the existing HTTP/MCP/CLI/investigation workflows.

Success is measured by information gain per call, unique graph edges, decision-changing context, reliability, and analyst utility rather than provider count.

## Chosen architecture

Three approaches were considered:

1. Add all candidate providers directly to existing workflows. Rejected because it increases latency, quota usage, semantic duplication, and policy risk.
2. Expose every source as a separate command. Rejected because it fragments normalization, provenance, and correlation.
3. Use one shared intelligence fabric with explicit execution modes and authorization policy. Chosen.

All capabilities share the provider registry, manifest validation, transport boundary, telemetry, normalization, graph, error-surface, and evidence model. Automatic enrichment uses only capabilities explicitly marked safe for fan-out.

## Execution modes

Providers or provider-native capabilities receive one mode:

- `enrich`: passive point lookup suitable for bounded automatic enrichment.
- `graph`: relationship expansion around established observables.
- `search`: explicit corpus search with separate paging limits.
- `monitor`: owned-asset or feed-oriented observation.
- `analysis`: explicit remote analysis operations; never automatic.
- `knowledge`: reference data used for guidance, not threat confidence.
- `sensitive`: privacy-sensitive exposure intelligence requiring explicit invocation and authorization context.

`full` enrichment does not imply permission to run `monitor`, `analysis`, or `sensitive` operations.

## Provider policy extensions

Extend the provider manifest with validated fields:

- `mode`
- `fanoutEligible`
- `sensitivity`: `public`, `owned_asset`, `pii`, `credential`, `secret`, or `sample`
- `authorization`: `none`, `tenant`, `verified_domain`, `owned_network`, `explicit_case`, or `explicit_action`
- `retentionClass`: `normal`, `restricted`, `ephemeral`, or `no_store`
- reuse the existing `distribution` field as the single export/redistribution policy source of truth; extend its validated values only if `summary_only` is needed
- optional `async`, `maxPages`, `maxRelationships`, `supportsHistorical`, `supportsSearch`, `supportsBulk`, `providerFamily`, and quota metadata.

Do not introduce a second licensing/export field that can contradict `distribution`. Unknown values or incomplete policy metadata fail provider registration.

## Observable expansion

Add first-class observable types while preserving strict canonicalization:

- `email`
- `package` using PURL as the canonical representation
- `tls-fingerprint` with explicit namespaced schemes
- `crypto-address` with network context where required
- `secret-fingerprint`, never raw secret values
- `legal-entity` as structured organization context
- `username`, reusing the existing User Scanner path but excluding it from automatic enrichment

Ambiguous values must be rejected rather than guessed.

## New semantic classes

Add distinct semantics so new evidence does not collapse into generic reputation:

- `credential_exposure`
- `infostealer_exposure`
- `passive_dns_history`
- `domain_ownership_history`
- `malware_configuration`
- `malware_similarity`
- `supply_chain`
- `anonymization_infrastructure`
- `web_archive_observation`
- `secret_exposure`
- `crypto_abuse`
- `legal_entity_context`
- `tls_malware_infrastructure`
- `exploit_maturity`
- `underground_mention`
- `defensive_knowledge`

Evidence-role logic must explicitly classify every semantic as direct, supporting, contextual, or knowledge-only.

## Existing-provider expansion first

Before adding redundant vendors, deepen integrations already present.

### VirusTotal

Add bounded relationship pivots between files, domains, IPs, URLs, and certificates when supported by entitlement. Relationship results normalize into the existing evidence graph.

### urlscan

Expand result parsing to bounded redirect, request-host, file-hash, TLS/certificate, linked-resource, technology, and final destination relationships. External markup must be removed before graph insertion.

### Censys

Keep point host/certificate lookup and add explicit search/history capabilities for hosts, certificates, and certificate-to-host observations where the current API entitlement supports them.

### Existing enterprise providers

Where current credentials expose richer native APIs, expand those capabilities before adding a second vendor covering the same semantic class.

## New capability groups

The architecture permits the following researched additions, subject to live documentation and entitlement verification during implementation.

### Open and low-friction capabilities

- VulnCheck Community/XDB for exploitation maturity
- deps.dev for package and dependency graphs
- SSLBL and YARAify for TLS/malware similarity context
- MITRE D3FEND for defensive knowledge
- Internet Archive CDX for historical web observations
- CERT Polska MWDB for malware configuration context
- Chainabuse for cryptocurrency-abuse context
- GitGuardian privacy-preserving secret-exposure checks
- Shadowserver for approved owned-asset monitoring

### Infrastructure history and identity

Support DNSDB, Validin, DomainTools-family capabilities, WhoisXML comparison, Spur, Netify, and Team Cymru. Commercially overlapping historical-DNS/ownership sources must not all enter default automatic workflows. One primary source plus explicit alternatives is preferred.

### Enterprise threat intelligence

Support Microsoft Threat Intelligence Graph, Recorded Future, Google Threat Intelligence, richer Spamhaus capabilities, and IBM X-Force as optional configured sources. Missing credentials are `unconfigured`, never runtime failures.

### Sensitive exposure intelligence

Support authorized HIBP, Hudson Rock, SpyCloud-style, and equivalent sources only through the `sensitive` lane. No automatic public IOC lookup may invoke them. Negative results mean only `no_result` for that source and query.

### Underground-intelligence provider family

Normalize Flashpoint, Flare, DarkOwl, and Intel 471 behind a shared provider-family interface for explicit search and context. The runtime may operate with one licensed backend. Additional vendors are admitted only for measured unique value or resilience.

## Adaptive orchestration

Automatic intelligence collection becomes two-phase.

Phase 1 runs the static policy-approved baseline for the selected profile.

Phase 2 may admit graph capabilities when:

1. baseline evidence provides a supported pivot;
2. the pivot answers a declared unresolved intelligence question;
3. the request context authorizes that mode;
4. deadline, quota, relationship, and call budgets remain;
5. the provider is configured and healthy;
6. expected signal is not materially duplicative.

The planner is deterministic and auditable. Runtime provider selection does not require an opaque model decision.

Examples include certificate-history pivots from infrastructure evidence, exploitation-maturity pivots for uncertain CVEs, dependency pivots from packages, and malware-infrastructure pivots from established configuration evidence.

## Authorization context

Introduce immutable server-trusted authorization context containing only relevant claims such as principal, case identifier, verified tenant/domain scope, approved owned-network scope, explicit analysis authorization, and requested mode.

Untrusted request fields cannot grant ownership or tenant privileges by themselves.

## Privacy, retention, and distribution

Sensitive values use restricted logging and retention. Raw secret material is never a generic observable.

Every evidence item inherits the provider's existing `distribution` policy. If `summary_only` is added, manifest validation, evidence normalization, report generation, and exporters must all recognize it consistently.

- `shareable`: normalized evidence may be exported.
- `summary_only`: only permitted derived summaries/references may leave internal output.
- `internal` / `internal_only`: preserve existing semantics and exclude or redact material wherever current policy requires.

Export and reporting enforce distribution centrally.

No absent result from an exposure-oriented source may be summarized as `safe`, `clean`, or equivalent.

## Evidence graph requirements

All external results continue through canonical normalization and retain provider, observable, semantic kind, verdict, timestamps, attributes, relationships, references, cache/retrieval metadata, parser version, integrity fingerprint, and evidence role.

New fields may add execution mode, sensitivity, retention, and effective distribution metadata.

Relationship insertion must canonicalize targets, reject invalid values, remove external markup, deduplicate edges, cap expansion, and preserve provider provenance.

## Supply-chain lane

Add `package` workflows:

`package/PURL -> version -> dependency -> advisory/CVE -> repository/project`

deps.dev is the primary new source. Existing OSV and vulnerability providers may correlate advisories and CVEs.

Direct and transitive vulnerability relationships must remain distinguishable.

## TLS and malware lane

Allow graph connections among sample hash, malware family, rule/similarity match, TLS fingerprint, certificate, domain, IP, URL, configuration, infrastructure endpoint, and campaign/botnet identifiers.

Existing MalwareBazaar, ThreatFox, VirusTotal, Censys, Hybrid Analysis, and new SSLBL/YARAify/MWDB-style capabilities participate according to their semantic role. Shared fingerprints alone are supporting context, not attribution proof.

## Owned-asset lane

Owned-asset reporting requires server-approved asset scope. Initial support remains passive/query-only. It must not silently initiate network activity.

## Knowledge plane

D3FEND and future knowledge sources enrich ATT&CK-linked defensive guidance and hunt construction. Knowledge observations cannot increase maliciousness or attribution confidence.

## MCP and HTTP surface

Preserve existing tools and endpoints for backward compatibility.

Expose normalized deeper operations through one intelligence capability namespace, for example:

- `intel.pivot`
- `intel.search`
- `intel.identity`
- `intel.asset`
- `intel.supply_chain`
- `intel.malware`
- `intel.knowledge`
- `intel.providers`

Request schemas remain operation-specific and reject unsupported fields.

## Provider-count strategy

Do not model every endpoint or enterprise backend as an independent automatic provider. Use capability methods inside adapters and provider-family abstractions for substitutable commercial sources. If the current hard provider cap becomes artificial after deduplication, increase it deliberately with invariant coverage rather than removing the bound.

## Cost and failure semantics

Maintain request-local security call limits and add quota-aware admission for free, ordinary quota, scarce, paginated-search, and explicit-analysis operations.

Normalize failures including unconfigured, entitlement/auth mismatch, rate limited, timeout, upstream unavailable, invalid schema, no result, partial result, policy denied, ownership required, and explicit-action required.

Provider failure is never negative intelligence.

## Test strategy

Implementation is test-driven.

New observable tests cover valid/invalid canonicalization, ambiguity, limits, type-confusion prevention, and export behavior.

Every provider adapter receives fixtures for positive results, legitimate no-result, malformed data, unexpected schemas, auth errors, rate limiting, timeout, upstream failure, oversized responses, pagination/relationship bounds, and reference/markup sanitization.

Policy tests prove that sensitive, monitor, and analysis modes cannot execute through ordinary enrichment; knowledge cannot raise threat confidence; restricted evidence cannot leak through shareable exports; missing credentials remain unconfigured; and untrusted callers cannot self-assert privileged scope.

Existing enrichment, batch, provider, mission, investigation, report, STIX, Maltego, CLI, and MCP behavior remain green unless deliberately versioned.

Release requires full Node/MAXX, provider invariants, MCP conformance, Maltego, PowerShell where applicable, CodeQL, secret-safety, PR-diff review, and deployment smoke checks. Production exact SHA is verified separately after merge.

## Implementation waves

Wave 0: fabric primitives, policy fields, observable extensions, authorization context, export controls, and tests.

Wave 1: deepen VirusTotal, urlscan, and Censys plus generic bounded graph pivots.

Wave 2: add high-value open/low-friction sources: VulnCheck/XDB, deps.dev, SSLBL/YARAify, D3FEND, Wayback, MWDB, Chainabuse, and privacy-preserving secret exposure where documented.

Wave 3: sensitive and owned-asset lanes including authorized exposure sources and Shadowserver-style reporting.

Wave 4: infrastructure history and enterprise providers according to credentials and entitlement.

Wave 5: normalized underground-intelligence provider family with the first actually licensed backend.

Each wave is independently reviewable and shippable.

## Provider admission metric

A working adapter does not automatically earn default-workflow placement. Benchmark providers against a fixed corpus and measure unique normalized facts, unique graph edges, freshness, p50/p95 latency, error rate, false-positive contribution, hunt pivot yield, context lift, decision-changing observations, cost per material unique observation, and redistribution constraints.

Duplicative generic-reputation sources remain explicit-only or are rejected.

## Security invariants

1. No caller-controlled outbound host.
2. Fixed HTTPS egress by default.
3. No secret reflection.
4. No implicit active network action from ordinary enrichment.
5. No implicit remote analysis operation.
6. No sensitive lookup from ordinary enrichment.
7. No privilege based solely on caller claims.
8. No provider failure converted to negative intelligence.
9. No knowledge result converted to threat evidence.
10. All loops, pages, calls, graph expansion, bodies, and outputs remain bounded.
11. Raw external markup never becomes a canonical observable.
12. Existing distribution policy remains the single export-policy source of truth.
13. Production changes flow through protected PR and verified deployment.

## Acceptance criteria

The design is implemented when:

- execution-mode and policy metadata are validated and visible through capability/meta output;
- new observable classes are deterministic and tested;
- ordinary enrichment remains backward-compatible and cannot invoke sensitive/monitor/analysis modes;
- VT/urlscan/Censys expose bounded graph-depth improvements;
- at least one new supply-chain, exploit-maturity, TLS/malware, historical-web, and knowledge source is live;
- sensitive and owned-asset lanes enforce authorization centrally;
- optional commercial sources register safely when unconfigured;
- graph correlation and exports respect semantic and distribution boundaries;
- representative HTTP/MCP/investigation E2E paths pass;
- full repository QA/security gates pass;
- production SHA and representative live paths are verified after merge.

## Final principle

PARA11AX maximizes information gain per provider call, not provider count. All useful API candidates may be represented as capabilities, but only the semantically appropriate subset executes for a given observable, intent, authorization context, quota budget, and evidence gap.

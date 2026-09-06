<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Evidence Schema v2

The gateway returns provider evidence without collapsing different source semantics into one score. Current Evidence v2 schema version is `2.0`.

#### Top-level enrichment envelope

Core fields:

- `schemaVersion`, `gatewayVersion`, `requestId`
- canonical `indicator` and `type`
- `queriedAt`, `profile`, `durationMs`
- `budget`: call limit/usage, request deadline and exhaustion flags
- `providerSummary`: `ok`, `failed`, `skipped`, `cached`
- `status`: `ok`, `partial` or `error`
- `evidence[]`, `relationships[]`, `failures[]`
- `correlation`
- optional `intelligence`: Intelligence Kernel v1.0 derived context on compatible IP `ok`/`partial` results
- `decision`: bounded explainable analyst decision support
- `evidenceGraph`: Evidence Graph v1.0 on normalized `ok`/`partial` results
- `guidance`: Guidance v1.0 on normalized `ok`/`partial` results
- `huntContext`
- `meta`: count/status-oriented cache/provider/capability state for the request

`partial` means useful evidence exists but coverage was incomplete. A provider outage, timeout, rate limit, call-budget/deadline skip or circuit-open state is not negative threat evidence.

`intelligence`, `evidenceGraph` and `guidance` are additive analytical projections. They do not replace Evidence v2 or change the legacy failure contract. Error envelopes do not manufacture those projections.

#### Evidence item

Each evidence item contains:

- `provider`
- canonical `indicator` and `type`
- `observation`
- `relationships`
- `references`
- `retrievedAt`
- `cacheState`
- `durationMs`
- `integrity`

##### Observation

`observation.kind` preserves source semantics such as registration, routing, scanner activity, reputation, exploit probability, known-exploited status, sandbox metadata, certificate metadata or ATT&CK knowledge.

Additional source-specific kinds include:

- `community_ioc_report` — TweetFeed.live community reporting context. `observed` means the IOC was reported, not independently confirmed malicious.
- `ransomware_post_reference` — RansomLook search located ransomware/DLS material referencing the pivot. It remains an adversary/public-source claim.
- `ransomware_victim_claim` — ransomware.live located an exact victim-website-domain claim. It remains an adversary claim rather than proof of compromise.
- `certificate_metadata` — contextual X.509 metadata from an explicit certificate SHA-256 lookup. Presence, reuse, subject/issuer names or associated infrastructure do not become a malware-reputation vote.

These claim/report/context kinds deliberately remain separate from malware-reputation semantics. Cross-source repetition is not automatically independent confirmation.

`observation.verdict` is provider/parser semantic output. It is not normalized into a global maliciousness value.

Optional fields include `confidence`, `firstSeen`, `lastSeen`, `tags`, `malwareFamily`, `actor` and bounded `attributes`.

##### Integrity

`integrity` contains:

- `parserVersion`: parser/source contract revision used for normalization
- `rawHash`: SHA-256 over the provider adapter result before evidence normalization, when available
- `fingerprint`: deterministic SHA-256 over canonical normalized evidence content and parser version

The fingerprint is a reproducibility/provenance control, not a signature or authenticity proof for the upstream source.

#### Relationships

Evidence v2 relationships are investigation pivots expressed by normalized provider data. They include target type/value, relation semantics and provider provenance where available. Duplicate relationships are removed and bounded.

Ransomware groups referenced by claim adapters use the `ransomware_group` target type rather than `actor`, so a leak-site claim cannot accidentally create attribution confidence.

Infrastructure proximity, shared ASN, hosting, certificate reuse or common malware does not by itself establish actor attribution. Attribution confidence is emitted only when an explicit actor relationship exists.

#### Correlation

The correlation object retains separate analytical dimensions:

- `corroboration[]`: compatible same-class observations from multiple providers
- `contradictions[]`: opposing observations in the same semantic class
- `freshness`: current / aging / stale / unknown
- `evidenceQuality`: compatibility support quality; not maliciousness
- `threatAssessment`: typed support state for applicable reputation evidence
- `huntability`: bounded operational level and rationale
- `assessment`: compact report-compatibility mirror
- de-duplicated `relationships`
- for CVEs, `riskAxes.kev`, `riskAxes.epss`, `riskAxes.cvss`
- optional `attributionConfidence` from explicit relationships

Scanner/noise, Tor, registration/routing, certificate context and ATT&CK knowledge classes are excluded from malware-reputation corroboration. Community IOC reports and ransomware claims remain separate semantic classes.

#### Intelligence Kernel v1.0

Top-level `intelligence` is **deterministic derived context, not Evidence v2**. The current implementation is an IP reference policy. It consumes already-normalized evidence, explicit relationships, correlation and coverage metadata; it does not perform provider calls, mutate evidence or create a new observation.

Core bounded fields include:

- `schemaVersion: "1.0"`, observable `type`, and policy identity/version;
- `evidenceStrength`: `none | weak | moderate | strong` plus reasons;
- `sourceDiversity`: provider/source-role/semantic diversity and direct-vs-context distribution;
- `corroboration`: evidence-backed agreement with independence state;
- `contradiction`: severity plus conflicting semantic-class/provider/evidence detail;
- `temporalRelevance`: current/aging/stale/unknown distribution, first/last observed and span derived from observation timestamps;
- `relationshipValue`: stable identities over explicit supported relationships;
- `pivotCandidates`: bounded explicit **one-hop pivots**, ranked deterministically;
- `threatContext`: direct/supporting/contextual threat-relevant material kept distinct;
- `huntRelevance`: bounded search/telemetry/hunt viability;
- `coverageImpact`: duplicate-capability loss distinguished from materially unique capability loss;
- `analystPriority`: `immediate | investigate | monitor | contextual | insufficient` plus explicit reasons;
- `limitations[]` and deterministic `ruleIds[]`.

Important invariants:

- Kernel output **does not become Evidence v2** and never receives an Evidence v2 fingerprint as though it were a provider observation.
- Every evidence-backed derived conclusion references valid evidence fingerprints/providers; purely rule-derived conclusions identify the deterministic rule.
- `retrievedAt` is not used as an observation first/last-seen substitute.
- failed/skipped/absent providers remain coverage state, not negative threat evidence.
- contradictions are not silently resolved.
- free-text attributes do not manufacture related infrastructure.
- pivots are explicit one-hop relationships only and are bounded.
- no LLM, adaptive model, runtime learning or universal maliciousness score participates.
- the Kernel adds no network egress, secret/environment read, persistence or dependency surface.

If Kernel projection fails, otherwise valid enrichment remains valid and records `intelligence_projection_unavailable`; Evidence v2 is not discarded.

#### Decision support

`decision` is deterministic analyst decision support. For a compatible same-type Intelligence Kernel v1.0 projection, the current IP path can map Kernel analyst priority/evidence strength into disposition/confidence/reasons. If the Kernel is absent, malformed, wrong-version or wrong-type, the established deterministic Decision Support fallback remains intact.

Core fields:

- `version`
- `disposition`: one of `hunt_now`, `investigate`, `monitor`, `context_only`, `insufficient`
- `confidence`: `high`, `medium` or `low`
- `reasons[]`
- `assessment`
- `telemetry`: required Microsoft hunting tables/readiness and `environmentValidated: false` until the analyst verifies actual telemetry
- `temporal`
- `attackMappings[]`: only explicit supported ATT&CK IDs
- `entityGraph`: compact bounded decision-local investigation pivots
- `huntPlan[]`: bounded KQL templates with telemetry, evidence fingerprints, false-positive notes and tuning guidance
- for CVEs, separate KEV/EPSS/CVSS `riskAxes`

Generated KQL is a starting hypothesis, not proof of compromise. `telemetry.environmentValidated` remains false because the gateway does not query a client SIEM schema, retention or ingestion health.

#### Evidence Graph v1.0

Top-level `evidenceGraph` is the canonical graph projection of normalized Evidence v2 with schema version `1.0`.

It remains distinct from both Decision Support and the Intelligence Kernel:

- `decision.entityGraph` is a compact decision-support view.
- `evidenceGraph` is a stable projection over explicit Evidence v2 facts and supported relationships.
- Kernel `relationshipValue` / `pivotCandidates` are derived context and are not injected as new Evidence Graph edges.
- the browser-local case graph is a separate projection over local case/snapshot/exact-sighting state.

Evidence Graph properties:

- deterministic SHA-256-derived stable node/edge identity
- deterministic ordering and bounded categories
- explicit-only observable, evidence, ATT&CK, actor and malware facts
- provider/evidence fingerprints retained where required
- fail-closed validation
- no free-form entity extraction
- no infrastructure-to-actor inference
- no new provider call, credential lookup, network egress or persistence path

A graph edge means supported source data expressed that relationship under graph rules. It is not proof of compromise or attribution.

#### Guidance v1.0

Top-level `guidance` is a deterministic analyst guidance projection with schema version `1.0`.

Guidance does not recalculate a second universal score. It inherits Decision Support vocabulary and existing Evidence Graph fingerprint validation. When a compatible Kernel projection exists, Guidance can include only a bounded intelligence summary: evidence strength, analyst priority, threat state, coverage impact, limitations and trace rule IDs. Raw Kernel relationships/pivots/observations are not copied into Guidance.

Other Guidance content can include:

- inherited `disposition` and `confidence`
- evidence fingerprints resolving to canonical Evidence Graph evidence nodes
- reasons/limitations
- freshness/coverage context
- contradictions
- telemetry requirements/readiness
- explicit ATT&CK mappings
- bounded hunt-plan context
- deterministic semantic-change attention context

Guidance remains an explanation/projection layer, not a new evidence source.

#### Operator context is not Evidence v2

Specialist analyst utilities use separate output contracts. User Scanner, native Shodan, and GreyNoise Project Swarm session/pivot results are **operator context, not Evidence v2**. Their presence in a terminal or Investigation Workspace does not create an Evidence v2 item, provider fingerprint, corroboration vote, maliciousness, ATT&CK mapping, attribution fact or analyst disposition.

GreyNoise has two distinct surfaces:

- canonical `gn`/GreyNoise provider execution can return normalized Evidence v2 from the fixed authenticated v3 IP lookup under provider semantics;
- `swarm search`, `swarm get`, `swarm unique`, and `swarm timeseries` return bounded session operator records through `/api/para11ax/swarm`.

A compatible Swarm read result may be explicitly recorded by `investigation capture operator`. That action preserves the operator-context authority label. `swarm export` returns one explicit bounded PCAP/raw download and does not replace the current operator result or become automatic Evidence v2/investigation evidence.

Session presence, GreyNoise classification/tags, source/destination pivots, JA3/JA4, Suricata fields, counts/trends and packet/raw bytes remain contextual source material. They require analyst interpretation and do not automatically prove compromise, exploitability, protected-environment relevance or attribution.

#### Browser-local case graph

Browser-local cases are not part of the server Evidence v2 schema. Cases can retain bounded snapshots/diffs, build exact typed cross-case sightings, and project a local graph from pins/snapshots/supported facts. Free-form notes are not parsed into entities. IndexedDB does not create server-side case persistence or IOC history.

Investigation Workspace v2 can separately retain explicitly captured operator context with its own authority label. It does not rewrite that context into the Evidence v2 schema.

#### Caching semantics

Only successful provider observations are cached. Successful semantic negatives such as `not_listed`, `not_found`, `no_result` and `no_association` use the adapter's shorter negative TTL. Timeout, HTTP, transport, parsing and provider failures are never cached.

`cacheState` is provenance about retrieval path, not source freshness. Source freshness is calculated separately.

#### Batch

Batch results preserve original input order. Canonically duplicated inputs reuse one enrichment result and contain `duplicateOf`. Invalid items have `status: invalid` independently; they do not reject otherwise valid batch work.

#### STIX export

STIX export is derived only from gateway-generated Evidence v2. It does not turn Intelligence Kernel conclusions or specialist operator context (including GreyNoise Project Swarm) into new evidence, threat confidence or attribution. MITRE source STIX IDs are preserved when available; object count is capped at 100.

There is no universal maliciousness score anywhere in Evidence v2, Intelligence Kernel v1.0, Evidence Graph v1.0 or Guidance v1.0.

Error envelopes do not add evidenceGraph or guidance; failed requests do not manufacture derived analytical projections.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
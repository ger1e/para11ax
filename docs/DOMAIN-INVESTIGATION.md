<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# Domain Investigation v1

Domain Investigation v1 is a deterministic suspicious-domain investigation workflow built on PARA11AX Evidence v2. It combines passive gateway evidence, existing Webamon evidence, bounded analyst-imported surface/vulnerability findings, provider-independence policy, explicit analyst evidence promotion, IOC correlation, conservative block guidance, STIX 2.1 export, a SOC-readable report, a compact next-agent handoff, and a derived Evidence Graph authority/provenance projection.

It does **not** execute active discovery, vulnerability scanning, arbitrary HTTP fetches, shell commands, or provider calls. Active discovery/scanning remains an explicit, separately authorized operator action outside this workflow. Imported scanner output is contextual material only and is never silently promoted into Evidence v2 or an analyst attestation.

## Authority model

Domain Investigation accepts one canonical domain Evidence v2 enrichment with `schemaVersion: "2.0"`. The supplied enrichment remains the authoritative passive source and is carried internally so deterministic rebuilds can occur after imports. Public `show`/report/handoff projections do not expose the internal `_authoritative` field.

Authority classes are intentionally separate:

- `evidence_v2`: canonical provider evidence supplied by the PARA11AX gateway.
- `operator_context`: bounded surface-discovery or vulnerability findings explicitly imported by the analyst. Candidate generation grants no authority.
- `analyst_promoted` / `analyst_attestation`: an immutable analyst-approved attestation derived from one bounded operator artifact through an explicit promotion event.

`operator_context` and analyst attestations can corroborate direct provider evidence for analyst review, but neither class becomes a provider-family vote. Registration, routing, internet exposure, certificate context, shared infrastructure, Webamon observations, and other contextual evidence likewise do not become direct malicious votes merely because they exist.

Promotion lifecycle events are append-only and deterministic. Supported decisions are `approved`, `rejected`, `revoked`, `superseded`, and `expired`; effective attestations are derived from that history. At most one effective attestation exists for a source-observable-claim tuple, and recursive promotion is not permitted.

Webamon is reused through the existing `webamon` provider evidence already present in Evidence v2. Domain Investigation does not create a second Webamon execution path.

## Provider independence

Provider names are provenance labels, **not independence votes**. A provider may contribute to a known `independenceGroup` only when the resolver has sufficient lineage metadata and `quorumEligible: true`.

The resolver records provider, independence group, lineage confidence, basis, references, update timestamp, and quorum eligibility. Missing or unknown lineage can retain a display/provenance bucket such as `provider:<name>`, but that bucket is explicitly non-quorum. Unknown lineage therefore never creates a second independent vote and never establishes `BLOCK` quorum.

Analyst attestations are a separate authority class. They can increase actionability or corroborate one known direct-malicious provider family, but they never increment provider-family quorum.

## Workflow

```text
canonical domain Evidence v2
  -> Domain Investigation build
  -> optional authorized surface import
  -> optional authorized vulnerability import
  -> zero-authority promotion candidates
  -> optional explicit analyst approve / reject / revoke events
  -> provider-independence resolution
  -> deterministic IOC correlation
  -> recommendation rules
  -> public projection / report / STIX / handoff
  -> derived Evidence Graph projection
```

Imports replace the corresponding imported set atomically. A failed validation or promotion decision leaves the previous artifact unchanged. Shell state is volatile; MCP state is client-carried. No server-side Domain Investigation authority store is introduced.

## Imported data bounds

Surface and vulnerability imports are deliberately narrow:

- maximum 500 records per imported set;
- maximum encoded import size 2 MiB;
- maximum accepted scalar field length 4,096 characters;
- imported values must be scalar strings, numbers, or booleans;
- nested objects and arrays are rejected;
- references must be valid HTTP(S) URLs;
- credential-bearing URLs are rejected;
- imported records receive deterministic `SURF-` or `VULN-` identifiers.

Approved surface fields are `host`, `ip`, `url`, `port`, `protocol`, `service`, `technology`, `status`, `source`, and `reference`.

Approved vulnerability fields are `host`, `url`, `templateId`, `cve`, `severity`, `title`, `matchedAt`, `source`, and `reference`.

No imported field is interpreted as stolen credentials or retained as a credential store. Promotion candidates are generated only from bounded eligible operator artifacts; a candidate itself has zero authority.

## IOC projection

The workflow normalizes and deduplicates explicit observables into these types:

`domain` · `url` · `ip` · `hash` · `asn` · `certificate` · `cve`

Each IOC retains bounded provenance such as provider names, Evidence v2 fingerprints, provider-independence groups, operator record IDs, explicit relationships, promotion event/attestation identifiers, and authority classes. Correlation is exact and deterministic. Arbitrary prose is not parsed to manufacture observables.

## Recommendation rules

Recommendations are advisory and require human approval before enforcement.

- `BLOCK`: at least two distinct **known quorum-eligible provider independence groups** supply direct malicious support for the exact IOC and there is no blocking contradiction.
- `BLOCK_CANDIDATE`: one known direct-malicious provider family plus independent corroborating operator context or an effective analyst attestation, or comparable review-worthy evidence that does not satisfy the two-family `BLOCK` rule.
- `MONITOR`: promoted/context-only support, a single direct-malicious family without sufficient independent corroboration, or malicious-looking provider evidence whose lineage is unknown/non-quorum.
- `DO_NOT_BLOCK`: no qualifying direct malicious provider evidence supports blocking the IOC.

The artifact emits explicit `ruleId`, direct/context source lists, contradictions, authority classes, independence metadata, quorum groups, and reasons. There is no universal maliciousness score. A provider name alone cannot satisfy independence, and an analyst attestation cannot substitute for a provider-family vote.

## Evidence Graph projection

The existing deterministic Evidence Graph is extended additively with authority/provenance projection. It can represent `independence_group`, `operator_artifact`, `promotion_candidate`, `promoted_evidence`, `promotion_event`, and `recommendation` nodes plus their provenance/quorum relationships.

Important boundary: the graph is a **derived explanation/projection**, not an authority input. Graph nodes or edges never feed back into promotion state, provider-independence resolution, or recommendation authority. `quorum_from` edges are emitted only for known `quorumEligible` independence groups; unknown lineage never receives one.

## Shell

The same volatile workflow is available on Web and CLI:

```text
domain-investigation build <gateway-enrichment-json>
domain-investigation build --file <path>
domain-investigation build --stdin

domain-investigation surface-import <surface-json>
domain-investigation surface-import --file <path>
domain-investigation surface-import --stdin

domain-investigation vulnerability-import <vulnerability-json>
domain-investigation vulnerability-import --file <path>
domain-investigation vulnerability-import --stdin

domain-investigation show
domain-investigation report
domain-investigation stix
domain-investigation handoff
domain-investigation promotion-candidates
domain-investigation promote <approval-json>
domain-investigation reject-promotion <decision-json>
domain-investigation revoke-promotion <decision-json>
domain-investigation graph
domain-investigation clear
```

Shell state is volatile only. Browser reboot/disconnect clears it; CLI state exists only inside the current process/pipeline. No Domain Investigation command requests provider/scanner capability or performs network egress.

`promotion-candidates` derives zero-authority candidates from eligible imported operator artifacts. `promote`, `reject-promotion`, and `revoke-promotion` append explicit deterministic lifecycle events atomically. `graph` returns the derived Evidence Graph projection and does not become authority state. `show` returns the sanitized public artifact. `report` returns deterministic text. `stix` returns the bounded STIX bundle. `handoff` returns compact continuation state. `clear` discards the volatile artifact.

## MCP

MCP exposes one grouped stateless tool:

`para11ax_domain_investigation`

Actions:

`build` · `surface_import` · `vulnerability_import` · `show` · `report` · `stix` · `handoff` · `promotion_candidates` · `promote` · `reject_promotion` · `revoke_promotion` · `graph`

The MCP server stores no hidden Domain Investigation session. Stateful transitions are client-carried: build/import/promotion transitions return the full artifact needed for the next transition, while public projections remain sanitized. `graph` returns a derived projection only and is not persisted server-side as authority.

Authenticated Domain Investigation requests use the larger bounded body allowance required for client-carried artifacts/imports. The allowance is scoped to this grouped tool rather than raising the public MCP ceiling globally. Promotion decision payloads are separately bounded, and unauthenticated requests remain behind the normal public ceiling and OAuth/gateway authorization rules.

## STIX 2.1

Domain Investigation exports deterministic bounded STIX 2.1 from the correlated IOC projection. Domain, URL, IP, supported hashes and ASN values use existing PARA11AX STIX utilities; CVEs export as vulnerability objects rather than fabricated indicator patterns.

The exporter is capped at 100 objects, preserves deterministic ordering/IDs, accepts safe external references only, and does not invent provider references for operator-only findings.

Certificate IOCs remain available in Domain Investigation reports/handoff but are **not exported by the v1 Domain STIX adapter** because the existing PARA11AX STIX exporter does not yet expose a defensible certificate object/pattern mapping for this path.

## Report and handoff

The report states passive evidence/provider context, operator-context counts, IOC/recommendation counts, active-scanning boundary, limitations, provider-independence registry/quorum information, and analyst-attestation authority state.

The handoff is bounded to 128 KiB and contains:

- target identity;
- phase state and gaps;
- provider names and Evidence v2 fingerprints;
- provider-independence registry/quorum summary and unknown-lineage count;
- operator record IDs;
- effective analyst attestation IDs/fingerprints and promotion-event counts;
- contradiction summary;
- unresolved pivots;
- block/block-candidate action items requiring review;
- limitations;
- bounded next actions;
- context-budget metadata.

Raw Evidence v2 bodies, raw scanner datasets, promotion reason prose, and credentials are excluded from the handoff.

## Verification

Repository verification covers the core workflow, canonical gateway schema contract, provider-independence fail-closed semantics, promotion lifecycle, deterministic authority graph, Web/CLI command parity, stateless MCP catalog/conformance, deterministic STIX export, and bounded handoff behavior. Tooling smoke is the protected-branch gate and CodeQL runs alongside it.

## Security boundary

Domain Investigation adds no new provider, host, credential, persistence mechanism, arbitrary execution primitive, or active scanning path. Its core, promotion lifecycle, and graph/STIX projections are deterministic transformations over already supplied data. Provider names are not treated as independent confirmation, unknown lineage is non-quorum, analyst attestations are corroboration rather than provider votes, and the Evidence Graph remains projection-only. Existing PARA11AX gateway validation, fixed egress, OAuth/bearer policy, and analyst-approval boundaries remain authoritative.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# Domain Investigation v1

Domain Investigation v1 is a deterministic suspicious-domain investigation workflow built on PARA11AX Evidence v2. It combines passive gateway evidence, existing Webamon evidence, bounded analyst-imported surface/vulnerability findings, IOC correlation, conservative block guidance, STIX 2.1 export, a SOC-readable report, and a compact next-agent handoff.

It does **not** execute active discovery, vulnerability scanning, arbitrary HTTP fetches, shell commands, or provider calls. Active discovery/scanning remains an explicit, separately authorized operator action outside this workflow. Imported scanner output is contextual material only and is never silently promoted into Evidence v2.

## Authority model

Domain Investigation accepts one canonical domain Evidence v2 enrichment with `schemaVersion: "2.0"`. The supplied enrichment remains the authoritative passive source and is carried internally so deterministic rebuilds can occur after imports. Public `show`/report/handoff projections do not expose the internal `_authoritative` field.

Authority classes are intentionally separate:

- `evidence_v2`: canonical provider evidence supplied by the PARA11AX gateway.
- `operator_context`: bounded surface-discovery or vulnerability findings explicitly imported by the analyst.

`operator_context` can corroborate a direct provider finding for analyst review, but it never becomes a direct malicious provider vote by itself. Registration, routing, internet exposure, certificate context, shared infrastructure, Webamon observations, and other contextual evidence likewise do not become direct malicious votes merely because they exist.

Webamon is reused through the existing `webamon` provider evidence already present in Evidence v2. Domain Investigation does not create a second Webamon execution path.

## Workflow

```text
canonical domain Evidence v2
  -> Domain Investigation build
  -> optional authorized surface import
  -> optional authorized vulnerability import
  -> deterministic IOC correlation
  -> recommendation rules
  -> public projection / report / STIX / handoff
```

Imports replace the corresponding imported set atomically. A failed validation leaves the previous artifact unchanged.

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

No imported field is interpreted as stolen credentials or retained as a credential store.

## IOC projection

The workflow normalizes and deduplicates explicit observables into these types:

`domain` · `url` · `ip` · `hash` · `asn` · `certificate` · `cve`

Each IOC retains bounded provenance such as provider names, Evidence v2 fingerprints, operator record IDs, explicit relationships, and authority classes. Correlation is exact and deterministic. Arbitrary prose is not parsed to manufacture observables.

## Recommendation rules

Recommendations are advisory and require human approval before enforcement.

- `BLOCK`: at least two distinct direct-malicious Evidence v2 providers support the exact IOC and there is no explicit negative contradiction.
- `BLOCK_CANDIDATE`: direct malicious Evidence v2 exists plus independent contextual/operator corroboration, or direct evidence is otherwise strong enough to warrant review but contradiction pressure prevents automatic `BLOCK`.
- `MONITOR`: only one direct source is present without independent corroboration, or only contextual/operator/provider observations exist.
- `DO_NOT_BLOCK`: no direct malicious Evidence v2 source supports blocking the IOC.

The artifact emits explicit `ruleId`, direct/context source lists, contradictions, authority classes, and reasons. There is no universal maliciousness score.

Provider-independence hardening is intentionally deferred to the follow-on architecture: v1 counts distinct provider identities. The planned follow-on introduces source-family-aware independence groups so wrappers over the same upstream cannot masquerade as independent confirmation.

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
domain-investigation clear
```

Shell state is volatile only. Browser reboot/disconnect clears it; CLI state exists only inside the current process/pipeline. No Domain Investigation command requests provider/scanner capability or performs network egress.

`show` returns the sanitized public artifact. `report` returns deterministic text. `stix` returns the bounded STIX bundle. `handoff` returns compact continuation state. `clear` discards the volatile artifact.

## MCP

MCP exposes one grouped stateless tool:

`para11ax_domain_investigation`

Actions:

`build` · `surface_import` · `vulnerability_import` · `show` · `report` · `stix` · `handoff`

The MCP server stores no hidden Domain Investigation session. Stateful transitions are client-carried: `build` and import actions return the full artifact needed for the next transition, while public projections remain sanitized.

Authenticated Domain Investigation requests use the larger bounded body allowance required for client-carried artifacts/imports. The allowance is scoped to this grouped tool rather than raising the public MCP ceiling globally. Unauthenticated requests remain behind the normal public ceiling and OAuth/gateway authorization rules.

## STIX 2.1

Domain Investigation exports deterministic bounded STIX 2.1 from the correlated IOC projection. Domain, URL, IP, supported hashes and ASN values use existing PARA11AX STIX utilities; CVEs export as vulnerability objects rather than fabricated indicator patterns.

The exporter is capped at 100 objects, preserves deterministic ordering/IDs, accepts safe external references only, and does not invent provider references for operator-only findings.

Certificate IOCs remain available in Domain Investigation reports/handoff but are **not exported by the v1 Domain STIX adapter** because the existing PARA11AX STIX exporter does not yet expose a defensible certificate object/pattern mapping for this path.

## Report and handoff

The report states the passive evidence count/providers, operator-context counts, IOC/recommendation counts, active-scanning boundary, and limitations.

The handoff is bounded to 128 KiB and contains:

- target identity;
- phase state and gaps;
- provider names and Evidence v2 fingerprints;
- operator record IDs;
- unresolved pivots;
- block/block-candidate action items requiring review;
- limitations;
- bounded next actions;
- context-budget metadata.

Raw Evidence v2 bodies, raw scanner datasets, and credentials are excluded from the handoff.

## Security boundary

Domain Investigation adds no new provider, host, credential, persistence mechanism, arbitrary execution primitive, or active scanning path. Its core and STIX projection are deterministic transformations over already supplied data. Existing PARA11AX gateway validation, fixed egress, OAuth/bearer policy, and analyst-approval boundaries remain authoritative.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
